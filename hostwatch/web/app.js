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

  function show(signedIn, username) {
    byId("login-view").hidden = signedIn;
    byId("app-view").hidden = !signedIn;
    byId("logout").hidden = !signedIn;
    byId("app-user").textContent = signedIn ? "Signed in as " + username + "." : "";
    byId(signedIn ? "main" : "username").focus();
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
