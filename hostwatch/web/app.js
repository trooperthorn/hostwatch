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
  var lastDoc = null;
  var prefs = { view: "expanded", groups: [] };
  var prefsLoaded = false;
  var prefsRetry = null;
  var hostOpen = {};
  var groupOpen = {};
  var idCounter = 0;
  var saveChain = Promise.resolve();
  var dragFrom = -1;

  // Status key to the vendored icon. The shapes differ, so status never rests on colour alone.
  var STATUS_ICON = { good: "circle-check", warning: "alert-triangle", critical: "circle-x", unknown: "circle-minus" };

  function el(tag, text, cls) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    if (cls) { node.className = cls; }
    return node;
  }

  function icon(name) {
    var node = el("span", null, "icon ic-" + String(name || "").replace(/[^a-z0-9-]/g, ""));
    node.setAttribute("aria-hidden", "true");
    return node;
  }

  function statusKey(key) { return STATUS_ICON[key] ? key : "unknown"; }

  // An icon plus the text label the server supplied, in a class that tints both.
  function statusMark(key, text) {
    var k = statusKey(key);
    var mark = el("span", null, "status stat-" + k);
    mark.appendChild(icon(STATUS_ICON[k]));
    mark.appendChild(el("span", text));
    return mark;
  }

  function keyed(node, key) { node.setAttribute("data-key", key); return node; }

  function focusKey(key) {
    var nodes = document.querySelectorAll("[data-key]");
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].getAttribute("data-key") === key && !nodes[i].disabled) { nodes[i].focus(); return true; }
    }
    return false;
  }

  // Every state, order, text and aggregate below comes from /api/v1/hosts/summary/grouped. Nothing
  // here compares a value to a limit, groups components or decides what is healthy. The only
  // choices made here are presentation: which view to draw and which groups the user asked to see.
  function labelText(labels) {
    var keys = Object.keys(labels || {});
    return keys.length ? keys.map(function (k) { return k + "=" + labels[k]; }).join(", ") : "none";
  }

  function stamp(ts) { return ts === null || ts === undefined ? "none" : new Date(ts * 1000).toLocaleString(); }

  function readingList(g) {
    var list = el("ul", null, "readings");
    g.members.forEach(function (m) {
      var li = el("li");
      li.appendChild(el("span", m.text + " "));
      li.appendChild(statusMark(m.status, m.status_text));
      list.appendChild(li);
    });
    if (!g.members.length) { list.appendChild(el("li", "No readings reported.")); }
    return list;
  }

  function expertTable(h, g) {
    var wrap = el("div", null, "table-wrap");
    var table = el("table", null, "expert-table");
    table.appendChild(el("caption", g.label + " readings on " + h.host + ". Raw values, units, labels, sources and times."));
    var head = el("tr");
    ["Reading", "Id", "Value", "Unit", "Labels", "Source", "Status", "Reason", "Timestamp"].forEach(function (t) {
      var th = el("th", t);
      th.setAttribute("scope", "col");
      head.appendChild(th);
    });
    var thead = el("thead");
    thead.appendChild(head);
    table.appendChild(thead);
    var body = el("tbody");
    g.members.forEach(function (m) {
      var tr = el("tr");
      tr.appendChild(el("td", m.label));
      tr.appendChild(el("td", m.id, "muted"));
      tr.appendChild(el("td", m.value === null || m.value === undefined ? "unavailable" : m.value));
      tr.appendChild(el("td", m.unit || "none"));
      tr.appendChild(el("td", labelText(m.labels), "grow"));
      tr.appendChild(el("td", m.source));
      var st = el("td");
      st.appendChild(statusMark(m.status, m.status_text));
      tr.appendChild(st);
      tr.appendChild(el("td", m.reason || "none"));
      tr.appendChild(el("td", stamp(m.ts), "nowrap"));
      body.appendChild(tr);
    });
    table.appendChild(body);
    wrap.appendChild(table);
    return wrap;
  }

  function groupCard(h, g, view) {
    var card = el("section", null, "group-card");
    card.setAttribute("data-status-key", statusKey(g.status));
    var id = "grp-" + (idCounter++);
    var title = el("span", null, "group-title");
    title.appendChild(icon(g.icon));
    title.appendChild(el("span", g.label));
    title.appendChild(statusMark(g.status, g.status_text));
    var summary = el("p", g.summary, "group-summary");
    if (view === "expert") {
      var heading = el("h4", null, "group-title");
      while (title.firstChild) { heading.appendChild(title.firstChild); }
      card.appendChild(heading);
      card.appendChild(summary);
      card.appendChild(expertTable(h, g));
      return card;
    }
    var key = h.host + "|" + g.id;
    var open = groupOpen[key] === true;
    var btn = el("button", null, "group-toggle");
    btn.type = "button";
    btn.setAttribute("aria-expanded", String(open));
    btn.setAttribute("aria-controls", id);
    keyed(btn, "g:" + key);
    btn.appendChild(title);
    btn.addEventListener("click", function () { groupOpen[key] = !open; renderCurrent(); });
    card.appendChild(btn);
    card.appendChild(summary);
    var body = el("div");
    body.id = id;
    body.hidden = !open;
    if (open) { body.appendChild(readingList(g)); }
    card.appendChild(body);
    return card;
  }

  // Groups the user hid that are warning or critical on this host. The server already counted them in the
  // host status and banner; this only names them so a hidden problem is never silent.
  function hiddenAttention(h) {
    var hidden = {};
    prefs.groups.forEach(function (p) { if (!p.visible) { hidden[p.id] = true; } });
    return h.groups.filter(function (g) {
      var k = statusKey(g.status);
      return hidden[g.id] && (k === "warning" || k === "critical");
    });
  }

  function attentionMarker(h) {
    var bad = hiddenAttention(h);
    if (!bad.length) { return null; }
    var m = el("span", null, "hidden-attention");
    m.setAttribute("role", "note");
    m.appendChild(icon("alert-triangle"));
    m.appendChild(el("span", "Hidden group needs attention: " + bad.map(function (g) {
      return g.label + " (" + g.status_text + ")";
    }).join(", ")));
    return m;
  }

  function hostHead(h) {
    var head = el("span", null, "host-head");
    head.appendChild(icon("server"));
    head.appendChild(el("span", h.host));
    head.appendChild(statusMark(h.status_key, h.status_text));
    var note = attentionMarker(h);
    if (note) { head.appendChild(note); }
    return head;
  }

  // The groups this user chose to see, in the order they chose, from the groups the host has.
  function visibleGroups(h) {
    if (!prefs.groups.length) { return h.groups; }
    var byGroup = {};
    h.groups.forEach(function (g) { byGroup[g.id] = g; });
    var out = [];
    prefs.groups.forEach(function (p) {
      if (p.visible && byGroup[p.id]) { out.push(byGroup[p.id]); }
    });
    return out;
  }

  function simpleHost(h) {
    var box = el("article", null, "host");
    box.setAttribute("data-status-key", statusKey(h.status_key));
    var head = el("div", null, "host-head");
    var title = el("h3");
    title.appendChild(icon("server"));
    title.appendChild(el("span", h.host));
    head.appendChild(title);
    head.appendChild(statusMark(h.status_key, h.status_text));
    var note = attentionMarker(h);
    if (note) { head.appendChild(note); }
    var chips = el("span", null, "chips");
    visibleGroups(h).forEach(function (g) {
      var chip = el("span", null, "chip");
      var name = g.label + ": " + g.status_text;
      chip.setAttribute("role", "img");
      chip.setAttribute("aria-label", name);
      chip.title = name;
      chip.appendChild(icon(g.icon));
      var k = statusKey(g.status);
      var mark = icon(STATUS_ICON[k]);
      mark.className += " stat-" + k;
      chip.appendChild(mark);
      chips.appendChild(chip);
    });
    head.appendChild(chips);
    box.appendChild(head);
    if (h.reason) { box.appendChild(el("p", h.reason, "muted")); }
    return box;
  }

  function cardsHost(h, view) {
    var box = el("article", null, "host");
    box.setAttribute("data-status-key", statusKey(h.status_key));
    var expert = view === "expert";
    var open = expert ? true : (hostOpen[h.host] === undefined ? h.status_key !== "good" : hostOpen[h.host]);
    var id = "host-" + (idCounter++);
    var heading = el("h3");
    if (expert) {
      heading.appendChild(hostHead(h));
    } else {
      var btn = el("button", null, "host-toggle");
      btn.type = "button";
      btn.setAttribute("aria-expanded", String(open));
      btn.setAttribute("aria-controls", id);
      keyed(btn, "h:" + h.host);
      btn.appendChild(hostHead(h));
      btn.addEventListener("click", function () { hostOpen[h.host] = !open; renderCurrent(); });
      heading.appendChild(btn);
    }
    box.appendChild(heading);
    var body = el("div");
    body.id = id;
    body.hidden = !open;
    if (open) {
      if (h.reason) { body.appendChild(el("p", h.reason, "muted")); }
      if (h.last_seen !== null && h.last_seen !== undefined) {
        body.appendChild(el("p", "Last seen " + stamp(h.last_seen), "muted"));
      }
      var groups = el("div", null, "groups");
      visibleGroups(h).forEach(function (g) { groups.appendChild(groupCard(h, g, view)); });
      body.appendChild(groups);
    }
    box.appendChild(body);
    return box;
  }

  function countText(counts) {
    return Object.keys(counts).map(function (k) {
      return k.charAt(0).toUpperCase() + k.slice(1) + " " + counts[k];
    }).join(", ");
  }

  function renderBanner(b) {
    byId("banner").setAttribute("data-status", String(b.status));
    byId("banner-icon").className = "icon ic-" + STATUS_ICON[statusKey(b.status_key)];
    byId("banner-badge").textContent = b.status_text;
    byId("banner-text").textContent = b.text;
    byId("banner-counts").textContent = "Hosts: " + countText(b.counts.hosts) + ". Groups: " + countText(b.counts.groups) + ".";
  }

  function renderCurrent() { if (lastDoc) { render(lastDoc); } }

  function render(doc) {
    lastDoc = doc;
    var active = document.activeElement ? document.activeElement.getAttribute("data-key") : null;
    renderBanner(doc.banner);
    var hosts = byId("hosts");
    hosts.className = "hosts " + prefs.view;
    clear(hosts);
    idCounter = 0;
    doc.hosts.forEach(function (h) {
      hosts.appendChild(prefs.view === "simple" ? simpleHost(h) : cardsHost(h, prefs.view));
    });
    renderCustomise();
    if (active) { focusKey(active); }
    byId("refresh-note").textContent = "Updated " + new Date(doc.generated * 1000).toLocaleTimeString() +
      ". Refreshes every " + doc_refresh_default() + " seconds.";
  }

  // Customise panel. The list is the user's saved order; moving or hiding a group saves it at once.
  function groupLabel(g) { return g.label || g.id; }

  function moveGroup(from, to) {
    var item = prefs.groups.splice(from, 1)[0];
    prefs.groups.splice(to, 0, item);
    savePrefs();
    renderCurrent();
  }

  function renderCustomise() {
    var list = byId("cust-list");
    var active = document.activeElement ? document.activeElement.getAttribute("data-key") : null;
    clear(list);
    var last = prefs.groups.length - 1;
    prefs.groups.forEach(function (g, i) {
      var li = el("li", null, "cust-row");
      li.draggable = true;
      li.addEventListener("dragstart", function (e) {
        dragFrom = i;
        li.classList.add("dragging");
        if (e.dataTransfer) { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", g.id); }
      });
      li.addEventListener("dragend", function () { dragFrom = -1; li.classList.remove("dragging"); });
      li.addEventListener("dragover", function (e) { if (dragFrom !== -1) { e.preventDefault(); } });
      li.addEventListener("drop", function (e) {
        e.preventDefault();
        if (dragFrom !== -1 && dragFrom !== i) {
          var from = dragFrom;
          dragFrom = -1;
          moveGroup(from, i);
          byId("cust-note").textContent = groupLabel(g) + " order changed.";
        }
      });
      li.appendChild(icon("grip-vertical"));
      var box = el("input");
      box.type = "checkbox";
      box.id = "cv-" + g.id;
      box.checked = g.visible;
      keyed(box, "cv:" + g.id);
      box.addEventListener("change", function () {
        g.visible = box.checked;
        savePrefs();
        renderCurrent();
        byId("cust-note").textContent = groupLabel(g) + (g.visible ? " is shown." : " is hidden.");
      });
      var label = el("label");
      label.setAttribute("for", box.id);
      label.appendChild(icon(g.icon));
      label.appendChild(el("span", groupLabel(g)));
      li.appendChild(box);
      li.appendChild(label);
      [["up", "Move up", "arrow-up", i - 1], ["down", "Move down", "arrow-down", i + 1]].forEach(function (d) {
        var btn = el("button");
        btn.type = "button";
        btn.setAttribute("aria-label", d[1] + ": " + groupLabel(g));
        btn.title = d[1];
        btn.appendChild(icon(d[2]));
        btn.disabled = d[3] < 0 || d[3] > last;
        keyed(btn, d[0] + ":" + g.id);
        btn.addEventListener("click", function () {
          moveGroup(i, d[3]);
          byId("cust-note").textContent = groupLabel(g) + " moved to position " + (d[3] + 1) + " of " + prefs.groups.length + ".";
          if (!focusKey(d[0] + ":" + g.id)) { focusKey((d[0] === "up" ? "down" : "up") + ":" + g.id); }
        });
        li.appendChild(btn);
      });
      list.appendChild(li);
    });
    if (active) { focusKey(active); }
  }

  function applyView() {
    ["simple", "expanded", "expert"].forEach(function (v) {
      byId("view-" + v).setAttribute("aria-pressed", String(prefs.view === v));
    });
  }

  function setView(name) {
    prefs.view = name;
    applyView();
    selectView("status");
    renderCurrent();
    savePrefs();
  }

  function savePrefs(extra) {
    // Groups are sent only after a successful load, so a failed load can never overwrite the saved order.
    var body = { view: prefs.view };
    if (extra && extra.reset) { body.reset = true; }
    else if (prefsLoaded) { body.groups = prefs.groups.map(function (g) { return { id: g.id, visible: g.visible }; }); }
    var note = byId("cust-note");
    saveChain = saveChain.then(function () {
      return apiSend("PUT", "/api/v1/me/preferences", body).then(function (resp) {
        if (resp.status === 401) { show(false, ""); return; }
        if (!resp.ok) { note.textContent = "Your choices could not be saved."; }
      });
    }).catch(function () { note.textContent = "Your choices could not be saved."; });
  }

  function prefsNotice(text) {
    var el = byId("prefs-notice");
    if (el) { el.textContent = text; el.hidden = !text; }
  }

  function loadPrefs() {
    return fetch("/api/v1/me/preferences", { credentials: "same-origin" }).then(function (resp) {
      return resp.ok ? resp.json() : null;
    }).then(function (doc) {
      if (doc) {
        prefs = { view: doc.view, groups: doc.groups, defaults: doc.default_groups };
        prefsLoaded = true;
        prefsNotice("");
      } else { prefsLoadFailed(); }
      applyView();
      renderCustomise();
    }).catch(function () { prefsLoadFailed(); applyView(); });
  }

  function prefsLoadFailed() {
    prefsNotice("Your saved dashboard layout could not be loaded. Changes to the group order are paused. Retrying.");
    if (!prefsRetry) {
      prefsRetry = setTimeout(function () {
        prefsRetry = null;
        if (!byId("app-view").hidden && !prefsLoaded) { loadPrefs().then(renderCurrent); }
      }, 15000);
    }
  }

  function resetPrefs() {
    var ids = prefs.defaults || prefs.groups.map(function (g) { return g.id; });
    var byGroup = {};
    prefs.groups.forEach(function (g) { byGroup[g.id] = g; });
    prefs.groups = ids.map(function (id) { var g = byGroup[id]; g.visible = true; return g; });
    savePrefs({ reset: true });
    renderCurrent();
    renderCustomise();
    byId("cust-note").textContent = "Default order restored and all groups shown.";
  }

  function toggleCustomise() {
    var btn = byId("customise-btn");
    var open = btn.getAttribute("aria-expanded") !== "true";
    btn.setAttribute("aria-expanded", String(open));
    byId("customise").hidden = !open;
    if (open) { selectView("status"); }
  }

  function stopRefresh() {
    if (refreshTimer !== null) { clearTimeout(refreshTimer); refreshTimer = null; }
  }

  function refresh() {
    stopRefresh();
    var wait = doc_refresh_default();
    fetch("/api/v1/hosts/summary/grouped", { credentials: "same-origin" }).then(function (resp) {
      if (resp.status === 401) { show(false, ""); return null; }
      if (!resp.ok) { throw new Error("status " + resp.status); }
      return resp.json();
    }).then(function (doc) {
      if (doc) { render(doc); refreshTimer = setTimeout(refresh, wait * 1000); }
    }).catch(function () {
      byId("banner").setAttribute("data-status", "2");
      byId("banner-icon").className = "icon ic-circle-x";
      byId("banner-badge").textContent = "Unreachable";
      byId("banner-text").textContent = "The hub could not be reached. The status below may be out of date.";
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
    tr.appendChild(el("td", new Date(e.ts * 1000).toLocaleString(), "nowrap"));
    tr.appendChild(el("td", e.host, "nowrap"));
    tr.appendChild(el("td", e.source, "nowrap"));
    tr.appendChild(el("td", e.kind, "nowrap"));
    tr.appendChild(el("td", e.severity, "sev-" + String(e.severity).replace(/[^a-z]/g, "")));
    tr.appendChild(el("td", e.title, "grow"));
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

  // Admin screens. Everything is served by /api/v1/admin/*, which answers 403 to a non-admin, so
  // the page only reveals the tabs when the keys listing succeeds. Hiding them is cosmetic; the
  // hub enforces the role. Reads go through apiGet and every state change goes through apiPost,
  // which sends the CSRF header.
  function apiGet(path) { return fetch(path, { credentials: "same-origin" }); }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  // The one-time secret lives in the DOM only while it is shown. Leaving the view, signing out,
  // creating another key, dismissing it or leaving the page removes it.
  function clearSecret() {
    byId("secret-value").textContent = "";
    byId("secret-box").hidden = true;
  }

  function setAdmin(isAdmin) {
    byId("tab-keys").hidden = !isAdmin;
    byId("tab-audit").hidden = !isAdmin;
  }

  function probeAdmin() {
    apiGet("/api/v1/admin/keys").then(function (resp) { setAdmin(resp.ok); }).catch(function () { setAdmin(false); });
  }

  function keyRow(k) {
    var tr = el("tr");
    tr.appendChild(el("td", k.id));
    tr.appendChild(el("td", k.prefix));
    tr.appendChild(el("td", k.owner));
    tr.appendChild(el("td", k.scopes.join(", ")));
    tr.appendChild(el("td", new Date(k.created * 1000).toLocaleString()));
    tr.appendChild(el("td", k.last_used ? new Date(k.last_used * 1000).toLocaleString() : "never"));
    tr.appendChild(el("td", k.revoked_at ? "Revoked" : "Active"));
    var cell = el("td");
    if (!k.revoked_at) {
      var ask = el("button", "Revoke");
      ask.type = "button";
      ask.setAttribute("aria-label", "Revoke key " + k.prefix + " owned by " + k.owner);
      ask.addEventListener("click", function () { confirmRevoke(cell, ask, k); });
      cell.appendChild(ask);
    }
    tr.appendChild(cell);
    return tr;
  }

  // Revoking asks a second time, in place, before the request is sent.
  function confirmRevoke(cell, ask, k) {
    ask.hidden = true;
    var yes = el("button", "Confirm revoke");
    yes.type = "button";
    yes.setAttribute("aria-label", "Confirm revoking key " + k.prefix + " owned by " + k.owner);
    var no = el("button", "Cancel");
    no.type = "button";
    no.addEventListener("click", function () {
      cell.removeChild(yes);
      cell.removeChild(no);
      ask.hidden = false;
      ask.focus();
    });
    yes.addEventListener("click", function () {
      yes.disabled = true;
      apiPost("/api/v1/admin/keys/" + encodeURIComponent(k.id) + "/revoke").then(function (resp) {
        if (resp.status === 401) { show(false, ""); return; }
        byId("keys-note").textContent = resp.ok ? "Key " + k.prefix + " was revoked." : "The key could not be revoked.";
        loadKeys();
      }).catch(function () {
        byId("keys-note").textContent = "The key could not be revoked.";
        yes.disabled = false;
      });
    });
    cell.appendChild(yes);
    cell.appendChild(no);
    yes.focus();
  }

  function loadKeys() {
    var body = byId("keys-body");
    apiGet("/api/v1/admin/keys").then(function (resp) {
      if (resp.status === 401) { show(false, ""); return null; }
      if (!resp.ok) { throw new Error("status " + resp.status); }
      return resp.json();
    }).then(function (doc) {
      if (!doc) { return; }
      clear(body);
      doc.keys.forEach(function (k) { body.appendChild(keyRow(k)); });
    }).catch(function () { byId("keys-note").textContent = "The keys could not be loaded."; });
  }

  function onCreateKey(event) {
    event.preventDefault();
    var scopes = Array.prototype.filter.call(document.querySelectorAll("#keys-form input[name=scope]"),
      function (box) { return box.checked; }).map(function (box) { return box.value; });
    var note = byId("keys-note");
    if (!scopes.length) { note.textContent = "Choose at least one scope."; return; }
    clearSecret();
    apiPost("/api/v1/admin/keys", { scopes: scopes, owner: byId("k-owner").value.trim() }).then(function (resp) {
      if (resp.status === 401) { show(false, ""); return null; }
      if (!resp.ok) { note.textContent = "The key could not be created. Check the owner and scopes."; return null; }
      return resp.json();
    }).then(function (doc) {
      if (!doc) { return; }
      byId("secret-value").textContent = doc.secret;
      byId("secret-box").hidden = false;
      note.textContent = "Key " + doc.key.prefix + " was created.";
      byId("k-owner").value = "";
      loadKeys();
      byId("secret-dismiss").focus();
    }).catch(function () { note.textContent = "The key could not be created."; });
  }

  // Audit log: filtering and paging are done by GET /api/v1/admin/audit, which has no write route.
  var auditCursor = null;

  function auditParams(cursor) {
    var q = new URLSearchParams();
    ["kind", "actor"].forEach(function (name) {
      var v = byId("a-" + name).value.trim();
      if (v) { q.set(name, v); }
    });
    var span = Number(byId("a-since").value);
    if (span > 0) { q.set("since", String(Date.now() / 1000 - span)); }
    q.set("limit", String(EVENT_PAGE));
    if (cursor) { q.set("before_id", String(cursor)); }
    return q.toString();
  }

  function auditRow(r) {
    var tr = el("tr");
    // Fixed-format columns stay on one line; path and detail wrap and take the spare width.
    [[new Date(r.ts * 1000).toLocaleString(), "nowrap"], [r.actor, "nowrap"], [r.kind, "nowrap"],
     [r.method, "nowrap"], [r.path, "path"], [r.status, "nowrap"], [r.remote, "nowrap"],
     [JSON.stringify(r.detail), "grow"]].forEach(function (c) { tr.appendChild(el("td", c[0], c[1])); });
    return tr;
  }

  function loadAudit(append) {
    var body = byId("audit-body");
    var note = byId("audit-note");
    apiGet("/api/v1/admin/audit?" + auditParams(append ? auditCursor : null)).then(function (resp) {
      if (resp.status === 401) { show(false, ""); return null; }
      if (!resp.ok) { throw new Error("status " + resp.status); }
      return resp.json();
    }).then(function (doc) {
      if (!doc) { return; }
      if (!append) { clear(body); }
      doc.rows.forEach(function (r) { body.appendChild(auditRow(r)); });
      auditCursor = doc.rows.length === EVENT_PAGE ? doc.rows[doc.rows.length - 1].id : null;
      byId("audit-more").hidden = auditCursor === null;
      note.textContent = body.children.length ? body.children.length + " rows shown." : "No audit rows match these filters.";
    }).catch(function () { note.textContent = "The audit log could not be loaded."; });
  }

  function selectView(name) {
    var events = name === "events";
    var history = name === "history";
    byId("status-panel").hidden = name !== "status";
    byId("events-panel").hidden = !events;
    byId("history-panel").hidden = !history;
    byId("keys-panel").hidden = name !== "keys";
    byId("audit-panel").hidden = name !== "audit";
    byId("tab-keys").setAttribute("aria-pressed", String(name === "keys"));
    byId("tab-audit").setAttribute("aria-pressed", String(name === "audit"));
    clearSecret();
    byId("tab-status").setAttribute("aria-pressed", String(!events && !history));
    byId("tab-events").setAttribute("aria-pressed", String(events));
    byId("tab-history").setAttribute("aria-pressed", String(history));
    if (events) { loadEvents(false); }
    if (history) { loadSeries(); }
    if (name === "keys") { loadKeys(); }
    if (name === "audit") { loadAudit(false); }
  }

  function show(signedIn, username) {
    if (!signedIn) { prefsLoaded = false; prefsNotice(""); stopRefresh(); clearSecret(); setAdmin(false); }
    byId("login-view").hidden = signedIn;
    byId("app-view").hidden = !signedIn;
    byId("logout").hidden = !signedIn;
    byId("viewbar").hidden = !signedIn;
    byId("app-user").textContent = signedIn ? "Signed in as " + username + "." : "";
    byId(signedIn ? "main" : "username").focus();
    if (signedIn) { loadPrefs().then(refresh); probeAdmin(); }
  }

  // State-changing requests carry the CSRF token in a header. The session cookie is HttpOnly
  // and never read here.
  function apiSend(method, path, body) {
    var headers = { "Content-Type": "application/json", "X-CSRF-Token": csrfToken || readCookie(CSRF_COOKIE) };
    return fetch(path, { method: method, headers: headers, credentials: "same-origin",
                         body: body === undefined ? undefined : JSON.stringify(body) });
  }

  function apiPost(path, body) { return apiSend("POST", path, body); }

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
    ["simple", "expanded", "expert"].forEach(function (v) {
      byId("view-" + v).addEventListener("click", function () { setView(v); });
    });
    byId("customise-btn").addEventListener("click", toggleCustomise);
    byId("cust-reset").addEventListener("click", resetPrefs);
    byId("tab-status").addEventListener("click", function () { selectView("status"); });
    byId("tab-events").addEventListener("click", function () { selectView("events"); });
    byId("tab-history").addEventListener("click", function () { selectView("history"); });
    byId("tab-keys").addEventListener("click", function () { selectView("keys"); });
    byId("tab-audit").addEventListener("click", function () { selectView("audit"); });
    byId("keys-form").addEventListener("submit", onCreateKey);
    byId("secret-dismiss").addEventListener("click", clearSecret);
    byId("audit-form").addEventListener("submit", function (e) { e.preventDefault(); loadAudit(false); });
    byId("audit-more").addEventListener("click", function () { loadAudit(true); });
    window.addEventListener("pagehide", clearSecret);
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
