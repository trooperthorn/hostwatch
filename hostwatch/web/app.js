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
    // An existing session shows the signed-in view; anything else shows the login form.
    fetch("/internal/v1/latest", { credentials: "same-origin" }).then(function (resp) {
      show(resp.ok, resp.ok ? "this session" : "");
    }).catch(function () { show(false, ""); });
  }

  start();
})();
