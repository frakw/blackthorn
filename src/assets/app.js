// blackthorn web UI: small enhancements. Every page works without this.
(function () {
  "use strict";

  // A poll that was sent to the login page means the session ended: go
  // there, rather than showing the login page's HTML as data.
  var loggedOut = function (r) {
    if (r.redirected && new URL(r.url).pathname === "/login") {
      window.location.assign("/login");
      return true;
    }
    return false;
  };

  // Ask before destructive forms.
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Keep the map current.
  var map = document.getElementById("map");
  if (map) {
    setInterval(function () {
      if (document.hidden) return;
      fetch(map.getAttribute("data-refresh"), { credentials: "same-origin" })
        .then(function (r) { return r.ok && !loggedOut(r) ? r.text() : null; })
        .then(function (svg) {
          if (svg && svg.indexOf("<svg") === 0) map.innerHTML = svg;
        })
        .catch(function () {});
    }, 15000);
  }

  // The terminal view: poll the screen, send keys without leaving the page.
  var screen = document.getElementById("screen");
  if (screen) {
    var refresh = function () {
      if (document.hidden) return;
      fetch(screen.getAttribute("data-src"), { credentials: "same-origin" })
        .then(function (r) { return r.ok && !loggedOut(r) ? r.text() : null; })
        .then(function (t) {
          if (t === null) return;
          var atBottom = screen.scrollHeight - screen.scrollTop - screen.clientHeight < 30;
          screen.textContent = t.replace(/\s+$/, "");
          if (atBottom) screen.scrollTop = screen.scrollHeight;
        })
        .catch(function () {});
    };
    refresh();
    setInterval(refresh, 2000);

    document.querySelectorAll("form.send").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        e.preventDefault();
        var body = new URLSearchParams(new FormData(f));
        fetch(f.action, { method: "POST", body: body, credentials: "same-origin", redirect: "manual" })
          .then(function () {
            var text = f.querySelector("input[name=text]");
            if (text) text.value = "";
            setTimeout(refresh, 300);
          });
      });
    });
  }
})();
