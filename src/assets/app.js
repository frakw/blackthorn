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

  var store = {
    get: function (k) {
      try { return JSON.parse(window.localStorage.getItem(k) || "null"); } catch (e) { return null; }
    },
    set: function (k, v) {
      try { window.localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private mode */ }
    },
    del: function (k) {
      try { window.localStorage.removeItem(k); } catch (e) { /* private mode */ }
    }
  };

  // Ask before destructive forms.
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Copy buttons. The clipboard API needs HTTPS; plain HTTP falls back to
  // selecting the text and the older copy command.
  // Rename pop-ups (<details class="pop">): focus the name, and close with
  // Cancel or Escape.
  document.querySelectorAll("details.pop").forEach(function (d) {
    var cancel = d.querySelector("[data-close]");
    if (cancel) {
      cancel.hidden = false;
      cancel.addEventListener("click", function () { d.open = false; });
    }
    d.addEventListener("toggle", function () {
      if (!d.open) return;
      document.querySelectorAll("details.pop[open]").forEach(function (o) { if (o !== d) o.open = false; });
      var i = d.querySelector("input:not([type=hidden])");
      if (i) { i.focus(); i.select(); }
    });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    document.querySelectorAll("details.pop[open]").forEach(function (o) { o.open = false; });
  });

  document.querySelectorAll("button[data-copy]").forEach(function (b) {
    b.hidden = false;
    b.addEventListener("click", function () {
      var el = document.getElementById(b.getAttribute("data-copy"));
      if (!el) return;
      var text = el.textContent;
      var done = function () {
        b.textContent = "Copied";
        setTimeout(function () { b.textContent = "Copy"; }, 1500);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () {});
        return;
      }
      var t = document.createElement("textarea");
      t.value = text;
      t.setAttribute("readonly", "");
      t.style.position = "fixed";
      t.style.opacity = "0";
      document.body.appendChild(t);
      t.select();
      try { if (document.execCommand("copy")) done(); } catch (e) { /* nothing to do */ }
      document.body.removeChild(t);
    });
  });

  // ------------------------------------------------------------ passkeys
  var canPasskey = !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
  var enc = function (buf) {
    var s = "";
    new Uint8Array(buf).forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  var dec = function (s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var b = atob(s), a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
    return a.buffer;
  };
  var csrfValue = function () {
    var i = document.querySelector("input[name=csrf]");
    return i ? i.value : "";
  };
  // A challenge from the hub: purpose login, register or step_up.
  var begin = function (purpose) {
    return fetch("/passkey/begin", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "purpose=" + purpose + "&csrf=" + encodeURIComponent(csrfValue())
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(j.error || "the hub refused");
        return j;
      });
    });
  };
  var getAnswer = function (o) {
    return navigator.credentials.get({ publicKey: {
      challenge: dec(o.challenge), rpId: o.rp_id, userVerification: "required", timeout: 60000,
      allowCredentials: o.credentials.map(function (id) { return { type: "public-key", id: dec(id) }; })
    } }).then(function (c) {
      return JSON.stringify({ id: c.id, client_data: enc(c.response.clientDataJSON),
        authenticator_data: enc(c.response.authenticatorData), signature: enc(c.response.signature) });
    });
  };
  var createAnswer = function (o) {
    return navigator.credentials.create({ publicKey: {
      challenge: dec(o.challenge), rp: { id: o.rp_id, name: o.rp_name },
      user: { id: dec(o.user_id), name: o.user_name, displayName: o.user_name },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none", timeout: 60000,
      excludeCredentials: o.credentials.map(function (id) { return { type: "public-key", id: dec(id) }; })
    } }).then(function (c) {
      return JSON.stringify({ id: c.id, client_data: enc(c.response.clientDataJSON),
        attestation: enc(c.response.attestationObject) });
    });
  };
  var say = function (el, msg) {
    if (!el) { window.alert(msg); return; }
    el.textContent = msg; el.hidden = !msg;
  };

  // Log in with a passkey.
  var pl = document.querySelector(".passkey-login");
  var plForm = document.getElementById("passkey-login");
  if (pl && plForm && canPasskey) {
    pl.hidden = false;
    pl.querySelector("[data-passkey-login]").addEventListener("click", function () {
      begin("login").then(getAnswer).then(function (a) {
        plForm.querySelector("input[name=answer]").value = a;
        plForm.submit();
      }).catch(function (e) { if (e.name !== "NotAllowedError") window.alert(e.message); });
    });
  }

  // Add a passkey (the code field above confirms it is you).
  document.querySelectorAll("form.passkey-add").forEach(function (f) {
    var err = f.querySelector(".dialog-error");
    if (!canPasskey) { say(err, "This browser cannot use passkeys here."); return; }
    f.addEventListener("submit", function (e) {
      if (f.querySelector("input[name=answer]").value) return;
      e.preventDefault();
      say(err, "");
      begin("register").then(createAnswer).then(function (a) {
        f.querySelector("input[name=answer]").value = a;
        f.submit();
      }).catch(function (x) { say(err, x.name === "NotAllowedError" ? "Cancelled." : x.message); });
    });
  });

  // Wherever a fresh code is asked: "Use a passkey" instead.
  if (document.body.getAttribute("data-passkey") === "1" && canPasskey) {
    document.querySelectorAll("form input[name=code]").forEach(function (input) {
      var f = input.form;
      if (!f || f.classList.contains("passkey-add")) return;
      var b = document.createElement("button");
      b.type = "button"; b.className = "link passkey-step"; b.textContent = "or use a passkey";
      input.parentNode.appendChild(b);
      b.addEventListener("click", function () {
        if (!f.reportValidity || !Array.prototype.every.call(f.elements, function (el) {
          return el === input || !el.willValidate || el.checkValidity();
        })) { if (f.reportValidity) { input.required = false; f.reportValidity(); input.required = true; } return; }
        begin("step_up").then(getAnswer).then(function (a) {
          input.removeAttribute("pattern"); input.removeAttribute("maxlength"); input.required = false;
          input.type = "hidden"; input.value = a;
          if (f.getAttribute("data-confirm") && !window.confirm(f.getAttribute("data-confirm"))) return;
          f.submit();
        }).catch(function (x) { if (x.name !== "NotAllowedError") window.alert(x.message); });
      });
    });
  }

  // ------------------------------------------------------------ the map
  var map = document.getElementById("map");
  if (map) initMap(map);

  function initMap(wrap) {
    var POS = "bt-map-pos5", VIEW = "bt-map-view5"; // v0.9 layout
    var NW = 230, SLOT_Y = 42, SLOT_ROW = 18, PAD = 16, FRAME_TITLE = 26;
    var svg, view, nodes, busy = false;
    var tools = document.querySelector(".graph-tools");
    if (tools) tools.hidden = false;
    wrap.classList.add("live");

    function setup() {
      svg = wrap.querySelector("svg");
      if (!svg) return;
      svg.removeAttribute("width");
      svg.removeAttribute("height");
      var vb = svg.viewBox.baseVal;
      var home = { x: vb.x, y: vb.y, w: vb.width, h: vb.height };
      nodes = {};
      var saved = store.get(POS) || {};
      svg.querySelectorAll("g.node").forEach(function (g) {
        var id = g.getAttribute("data-node");
        var m = /translate\(([-\d.]+),([-\d.]+)\)/.exec(g.getAttribute("transform") || "");
        var n = { g: g, x: m ? +m[1] : 0, y: m ? +m[2] : 0, w: +g.getAttribute("data-w") || NW };
        if (saved[id]) { n.x = saved[id][0]; n.y = saved[id][1]; }
        nodes[id] = n;
        place(n);
      });
      wires();
      view = store.get(VIEW) || null;
      if (!view) view = fitView(home);
      apply();
    }

    function place(n) { n.g.setAttribute("transform", "translate(" + n.x + "," + n.y + ")"); }

    function curve(x1, y1, x2, y2) {
      var dx = Math.max(Math.abs(x2 - x1) / 2, 50);
      return "M" + x1 + "," + y1 + " C" + (x1 + dx) + "," + y1 + " " + (x2 - dx) + "," + y2 + " " + x2 + "," + y2;
    }
    // Between two ports on the left sides of their nodes (map::wire_path_left).
    function curveLeft(x1, y1, x2, y2) {
      var dx = Math.max(Math.abs(x2 - x1) / 2, 60);
      return "M" + x1 + "," + y1 + " C" + (Math.min(x1, x2) - dx) + "," + y1 + " " + (x2 - dx) + "," + y2 + " " + x2 + "," + y2;
    }

    function height(n) { return n.g.querySelector(".node-body").height.baseVal.value; }

    // Frames follow their nodes.
    function frames() {
      svg.querySelectorAll(".frame[data-members]").forEach(function (f) {
        var b = null;
        f.getAttribute("data-members").split(" ").forEach(function (id) {
          var n = nodes[id];
          if (!n) return;
          var r = { x1: n.x, y1: n.y, x2: n.x + n.w, y2: n.y + height(n) };
          b = b ? { x1: Math.min(b.x1, r.x1), y1: Math.min(b.y1, r.y1), x2: Math.max(b.x2, r.x2), y2: Math.max(b.y2, r.y2) } : r;
        });
        if (!b) return;
        var rect = f.querySelector(".frame-body"), t = f.querySelector(".frame-title");
        var pad = +f.getAttribute("data-pad") || PAD;
        var x = b.x1 - pad, y = b.y1 - pad - FRAME_TITLE;
        rect.setAttribute("x", x); rect.setAttribute("y", y);
        rect.setAttribute("width", b.x2 - b.x1 + 2 * pad);
        rect.setAttribute("height", b.y2 - b.y1 + 2 * pad + FRAME_TITLE);
        if (t) { t.setAttribute("x", x + 12); t.setAttribute("y", y + 18); }
      });
    }

    function wires() {
      frames();
      svg.querySelectorAll(".wires [data-from]").forEach(function (el) {
        var a = nodes[el.getAttribute("data-from")], b = nodes[el.getAttribute("data-to")];
        if (!a || !b) return;
        var fp = +el.getAttribute("data-fp") || 0, tp = +el.getAttribute("data-tp") || 0;
        var left = el.getAttribute("data-fs") === "left";
        var x1 = left ? a.x : a.x + a.w, y1 = a.y + SLOT_Y + fp * SLOT_ROW, x2 = b.x, y2 = b.y + SLOT_Y + tp * SLOT_ROW;
        if (el.tagName.toLowerCase() === "path") {
          el.setAttribute("d", (left ? curveLeft : curve)(x1, y1, x2, y2));
        } else {
          el.setAttribute("x", (x1 + x2) / 2);
          el.setAttribute("y", (y1 + y2) / 2 - 6);
        }
      });
    }

    function bounds() {
      var b = null;
      Object.keys(nodes).forEach(function (id) {
        var n = nodes[id];
        var r = { x1: n.x, y1: n.y - PAD - FRAME_TITLE, x2: n.x + n.w, y2: n.y + height(n) + PAD };
        b = b ? { x1: Math.min(b.x1, r.x1), y1: Math.min(b.y1, r.y1), x2: Math.max(b.x2, r.x2), y2: Math.max(b.y2, r.y2) } : r;
      });
      return b;
    }

    function fitView(fallback) {
      var b = bounds();
      if (!b) return fallback;
      var pad = 30;
      return { x: b.x1 - pad, y: b.y1 - pad, w: b.x2 - b.x1 + 2 * pad, h: b.y2 - b.y1 + 2 * pad };
    }

    function apply() {
      // Keep the box's proportions to the element's, so zoom is uniform.
      var r = wrap.getBoundingClientRect();
      if (r.width && r.height) {
        var want = r.width / r.height, have = view.w / view.h;
        if (have < want) { var w = view.h * want; view.x -= (w - view.w) / 2; view.w = w; }
        else { var h = view.w / want; view.y -= (h - view.h) / 2; view.h = h; }
      }
      svg.setAttribute("viewBox", [view.x, view.y, view.w, view.h].join(" "));
    }

    function toSvg(e) {
      var r = wrap.getBoundingClientRect();
      return { x: view.x + (e.clientX - r.left) / r.width * view.w, y: view.y + (e.clientY - r.top) / r.height * view.h };
    }

    function zoom(k, cx, cy) {
      var w = Math.min(Math.max(view.w * k, 200), 8000);
      k = w / view.w;
      if (cx === undefined) { cx = view.x + view.w / 2; cy = view.y + view.h / 2; }
      view = { x: cx - (cx - view.x) * k, y: cy - (cy - view.y) * k, w: view.w * k, h: view.h * k };
      apply();
      store.set(VIEW, view);
    }

    // Pointers: one on a node drags it, one on the canvas pans, two pinch.
    var pts = {}, drag = null, pan = null, pinch = null, moved = false, captured = false;
    wrap.addEventListener("pointerdown", function (e) {
      if (e.button !== 0 && e.pointerType === "mouse") return;
      pts[e.pointerId] = { x: e.clientX, y: e.clientY };
      var ids = Object.keys(pts);
      moved = false;
      if (ids.length === 2) {
        drag = null; pan = null;
        var a = pts[ids[0]], b = pts[ids[1]];
        pinch = { d: Math.hypot(a.x - b.x, a.y - b.y), view: { x: view.x, y: view.y, w: view.w, h: view.h } };
        return;
      }
      var g = e.target.closest && e.target.closest("g.node");
      var p = toSvg(e);
      if (g && nodes[g.getAttribute("data-node")]) {
        var n = nodes[g.getAttribute("data-node")];
        drag = { n: n, dx: p.x - n.x, dy: p.y - n.y };
      } else {
        pan = { x: e.clientX, y: e.clientY, view: { x: view.x, y: view.y, w: view.w, h: view.h } };
        wrap.classList.add("panning");
      }
      busy = true;
      captured = false;
    });
    wrap.addEventListener("pointermove", function (e) {
      if (!pts[e.pointerId]) return;
      var start = pts[e.pointerId];
      if (Math.abs(e.clientX - start.x) + Math.abs(e.clientY - start.y) > 4) moved = true;
      if (pinch) {
        pts[e.pointerId] = { x: e.clientX, y: e.clientY };
        var ids = Object.keys(pts), a = pts[ids[0]], b = pts[ids[1]];
        if (!a || !b) return;
        var d = Math.hypot(a.x - b.x, a.y - b.y);
        if (!d) return;
        var v = pinch.view;
        view = { x: v.x, y: v.y, w: v.w, h: v.h };
        var c = toSvg({ clientX: (a.x + b.x) / 2, clientY: (a.y + b.y) / 2 });
        zoom(pinch.d / d, c.x, c.y);
        return;
      }
      if (!moved) return;
      // Capture only once it is a drag, so a plain click still follows links.
      if (!captured) {
        captured = true;
        try { wrap.setPointerCapture(e.pointerId); } catch (err) { /* old browsers */ }
      }
      if (drag) {
        var p = toSvg(e);
        drag.n.x = Math.round(p.x - drag.dx);
        drag.n.y = Math.round(p.y - drag.dy);
        drag.n.g.classList.add("dragging");
        place(drag.n);
        wires();
      } else if (pan) {
        var r = wrap.getBoundingClientRect();
        view.x = pan.view.x - (e.clientX - pan.x) / r.width * view.w;
        view.y = pan.view.y - (e.clientY - pan.y) / r.height * view.h;
        apply();
      }
    });
    function end(e) {
      delete pts[e.pointerId];
      if (pinch) { if (Object.keys(pts).length < 2) { pinch = null; store.set(VIEW, view); } }
      if (drag) {
        drag.n.g.classList.remove("dragging");
        if (moved) {
          var saved = store.get(POS) || {};
          saved[drag.n.g.getAttribute("data-node")] = [drag.n.x, drag.n.y];
          store.set(POS, saved);
        }
        drag = null;
      }
      if (pan) { pan = null; wrap.classList.remove("panning"); if (moved) store.set(VIEW, view); }
      if (!Object.keys(pts).length) busy = false;
    }
    wrap.addEventListener("pointerup", end);
    wrap.addEventListener("pointercancel", end);
    // A drag that ends on a node's link is not a click on it.
    wrap.addEventListener("click", function (e) {
      if (moved) { e.preventDefault(); e.stopPropagation(); moved = false; }
    }, true);
    wrap.addEventListener("wheel", function (e) {
      e.preventDefault();
      var p = toSvg(e);
      zoom(Math.exp(e.deltaY * (e.deltaMode === 1 ? 0.05 : 0.0015)), p.x, p.y);
    }, { passive: false });
    window.addEventListener("resize", function () { if (svg) apply(); });

    if (tools) tools.addEventListener("click", function (e) {
      var b = e.target.closest("button[data-map]");
      if (!b) return;
      var what = b.getAttribute("data-map");
      if (what === "in") zoom(1 / 1.25);
      if (what === "out") zoom(1.25);
      if (what === "fit") { view = fitView(view); apply(); store.set(VIEW, view); }
      if (what === "reset") { store.del(POS); store.del(VIEW); refresh(true); }
    });

    function refresh(force) {
      if (busy && !force) return;
      if (document.hidden && !force) return;
      fetch(wrap.getAttribute("data-refresh"), { credentials: "same-origin" })
        .then(function (r) { return r.ok && !loggedOut(r) ? r.text() : null; })
        .then(function (text) {
          if (!text || text.indexOf("<svg") !== 0 || (busy && !force)) return;
          wrap.innerHTML = text;
          setup();
        })
        .catch(function () {});
    }
    setup();
    setInterval(refresh, 15000);
  }

  // ------------------------------------------------- settings: address lists
  var dialog = document.getElementById("add-address");
  var picker = { you: null, peers: [] };
  if (dialog) {
    try { picker = JSON.parse(dialog.getAttribute("data-picker")) || picker; } catch (e) { /* keep empty */ }
  }
  var V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  var isV6 = function (s) { return /^[0-9a-fA-F:.]+$/.test(s) && s.indexOf(":") >= 0 && s.split("::").length <= 2; };
  var isIp = function (s) { return V4.test(s) || isV6(s); };
  var isSocket = function (s) {
    var m = /^\[([^\]]+)\]:(\d+)$/.exec(s) || /^([^:\[\]]+):(\d+)$/.exec(s);
    return !!m && isIp(m[1]) && +m[2] >= 1 && +m[2] <= 65535;
  };
  var hostOf = function (s) {
    var m = /^\[([^\]]+)\]:\d+$/.exec(s) || /^([^:\[\]]+):\d+$/.exec(s);
    return m ? m[1] : s;
  };
  var peerOf = function (ip) {
    for (var i = 0; i < picker.peers.length; i++) {
      if (picker.peers[i].ips.indexOf(ip) >= 0) return picker.peers[i];
    }
    return null;
  };
  var split = function (v) { return v.split(/[\s,]+/).filter(function (x) { return x; }); };

  document.querySelectorAll(".list-edit").forEach(function (box) {
    if (!dialog || typeof dialog.showModal !== "function") return;
    var raw = box.querySelector(".list-raw");
    var kind = box.getAttribute("data-kind");
    var chips = document.createElement("div");
    chips.className = "chips";
    box.appendChild(chips);
    box.classList.add("live");

    function render() {
      chips.textContent = "";
      var list = split(raw.value);
      if (!list.length) {
        var none = document.createElement("span");
        none.className = "none";
        none.textContent = "(empty)";
        chips.appendChild(none);
      }
      list.forEach(function (a) {
        var c = document.createElement("span");
        c.className = "addr";
        var code = document.createElement("code");
        code.textContent = a;
        c.appendChild(code);
        var ip = hostOf(a), p = peerOf(ip), note = [];
        if (picker.you === ip) note.push("this device");
        if (p) note.push(p.name + (p.hub ? " (this hub)" : "") + " · " + (p.online ? "online" : "offline"));
        else if (picker.peers.length && ip !== "0.0.0.0" && ip !== "::") note.push("not on the tailnet");
        if (note.length) {
          var s = document.createElement("small");
          s.textContent = note.join(" · ");
          c.appendChild(s);
        }
        var x = document.createElement("button");
        x.type = "button";
        x.title = "Remove " + a;
        x.textContent = "×";
        x.addEventListener("click", function () {
          raw.value = split(raw.value).filter(function (y) { return y !== a; }).join(", ");
          render();
        });
        c.appendChild(x);
        chips.appendChild(c);
      });
      var add = document.createElement("button");
      add.type = "button";
      add.className = "add";
      add.textContent = "+ Add";
      add.addEventListener("click", function () { open(box, raw, kind, render); });
      chips.appendChild(add);
    }
    render();
  });

  function open(box, raw, kind, render) {
    var input = dialog.querySelector("input[name=address]");
    var err = dialog.querySelector(".dialog-error");
    var sug = dialog.querySelector(".suggest");
    var form = dialog.querySelector("form");
    input.value = "";
    input.placeholder = kind === "socket" ? "100.80.0.6:7180" : "100.80.0.2";
    err.hidden = true;
    sug.textContent = "";
    var have = split(raw.value);
    var offer = function (value, label, note) {
      if (have.indexOf(value) >= 0) return;
      var b = document.createElement("button");
      b.type = "button";
      var t = document.createElement("span");
      t.textContent = label;
      b.appendChild(t);
      var s = document.createElement("small");
      s.textContent = note;
      b.appendChild(s);
      b.addEventListener("click", function () { input.value = value; check(); });
      sug.appendChild(b);
    };
    var withPort = function (ip) { return ip.indexOf(":") >= 0 ? "[" + ip + "]:7180" : ip + ":7180"; };
    if (kind === "socket") {
      picker.peers.filter(function (p) { return p.hub; }).forEach(function (p) {
        p.ips.forEach(function (ip) { offer(withPort(ip), "this hub on the tailnet", withPort(ip)); });
      });
      offer("0.0.0.0:7180", "every address of this hub", "0.0.0.0:7180");
    } else {
      if (picker.you) offer(picker.you, "the device you are on", picker.you);
      picker.peers.forEach(function (p) {
        p.ips.forEach(function (ip) {
          if (ip === picker.you) return;
          offer(ip, p.name + (p.hub ? " (this hub)" : ""), ip + " · " + (p.os || "?") + " · " + (p.online ? "online" : "offline"));
        });
      });
    }
    function check() {
      var v = input.value.trim();
      var msg = "";
      if (!v) msg = "Type an address, or pick one below.";
      else if (kind === "socket" && !isSocket(v)) msg = "Use address:port, e.g. 100.80.0.6:7180 or [fd7a:115c:a1e0::6]:7180.";
      else if (kind !== "socket" && !isIp(v)) msg = "That is not an IP address (like 100.80.0.2 or fd7a:115c:a1e0::2).";
      else if (have.indexOf(v) >= 0) msg = "It is in the list already.";
      err.textContent = msg;
      err.hidden = !msg;
      return !msg;
    }
    form.onsubmit = function (e) {
      if (e.submitter && e.submitter.value === "cancel") return;
      if (!check()) { e.preventDefault(); return; }
      have.push(input.value.trim());
      raw.value = have.join(", ");
      render();
    };
    input.oninput = function () { err.hidden = true; };
    dialog.showModal();
    input.focus();
  }

  // ------------------------------------------------------------ terminal
  // Poll the screen, send keys without leaving the page.
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

// Times in the browser's own time zone.
document.querySelectorAll("time[data-local]").forEach(function (t) {
  var d = new Date(t.getAttribute("datetime"));
  if (!isNaN(d)) {
    t.title = t.textContent + " UTC";
    t.textContent = d.toLocaleString();
  }
});

// A chat's page: new messages as they come, typing, files, slash commands.
(function () {
  "use strict";
  var pageEl = document.querySelector(".chat-page");
  if (!pageEl) return;
  var log = document.getElementById("chat-log");
  var stateEl = document.getElementById("chat-state");
  var feedUrl = pageEl.getAttribute("data-feed");
  var base = feedUrl.replace(/\/feed$/, "");
  var csrf = pageEl.getAttribute("data-csrf");
  var offset = pageEl.getAttribute("data-offset");
  var busy = false;
  var timer = null;

  var nearBottom = function () {
    return window.innerHeight + window.scrollY >= document.body.scrollHeight - 120;
  };
  var toBottom = function () { window.scrollTo(0, document.body.scrollHeight); };
  toBottom();

  var post = function (action, fields) {
    var body = new URLSearchParams();
    body.set("csrf", csrf);
    body.set("js", "1");
    Object.keys(fields).forEach(function (k) { body.set(k, fields[k]); });
    return fetch(base + "/" + action, { method: "POST", body: body, credentials: "same-origin" })
      .then(function (r) {
        if (r.redirected && new URL(r.url).pathname === "/login") {
          window.location.assign("/login");
          throw new Error("logged out");
        }
        return r.json();
      })
      .then(function (j) {
        if (j.error) throw new Error(j.error);
        return j;
      });
  };

  var showError = function (msg) {
    var p = document.getElementById("chat-error");
    if (!p) {
      p = document.createElement("pre");
      p.id = "chat-error";
      p.className = "flash err";
      stateEl.parentNode.insertBefore(p, stateEl);
    }
    p.textContent = msg;
    p.hidden = !msg;
  };

  var poll = function () {
    if (timer) window.clearTimeout(timer);
    var stick = nearBottom();
    fetch(feedUrl + "?from=" + encodeURIComponent(offset), { credentials: "same-origin" })
      .then(function (r) {
        if (r.redirected && new URL(r.url).pathname === "/login") {
          window.location.assign("/login");
          throw new Error("logged out");
        }
        return r.json();
      })
      .then(function (j) {
        if (j.error) return;
        if (j.reset) log.innerHTML = j.html;
        else if (j.html) log.insertAdjacentHTML("beforeend", j.html);
        offset = j.offset;
        if (stateEl.innerHTML !== j.state_html) {
          stateEl.innerHTML = j.state_html;
          wireKeys();
        }
        busy = j.state === "busy";
        if (window.btModel) window.btModel(j);
        if (stick && (j.html || j.reset)) toBottom();
      })
      .catch(function () { /* try again later */ })
      .then(function () {
        if (!document.hidden) timer = window.setTimeout(poll, busy ? 1200 : 2500);
      });
  };
  document.addEventListener("visibilitychange", function () { if (!document.hidden) poll(); });

  // Stop and the answers to a question: without leaving the page.
  var wireKeys = function () {
    stateEl.querySelectorAll("form.chat-key").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        e.preventDefault();
        post("key", { key: f.querySelector("[name=key]").value })
          .then(function () { showError(""); window.setTimeout(poll, 300); })
          .catch(function (err) { showError(err.message); });
      });
    });
  };
  wireKeys();
  timer = window.setTimeout(poll, 1500);

  var form = document.getElementById("composer");
  if (!form) return;
  var text = document.getElementById("chat-text");
  var plus = document.getElementById("plus");
  var menu = document.getElementById("plus-menu");
  var file = document.getElementById("chat-file");
  var slash = document.getElementById("slash");
  var attached = document.getElementById("attached");
  plus.hidden = false;

  var grow = function () {
    text.style.height = "auto";
    text.style.height = Math.min(text.scrollHeight, window.innerHeight * 0.4) + "px";
  };
  text.addEventListener("input", grow);

  // Files added to the next message, in order: { name, path (once saved),
  // preview (a picture's data URL), el }.
  var files = [];
  var pending = 0;

  var send = function () {
    var t = text.value.trim();
    var refs = files.filter(function (f) { return f.path; })
      .map(function (f) { return "@" + f.path; });
    if (!t && !refs.length) return;
    if (pending) { showError("A file is still being added."); return; }
    if (refs.length) t = (t ? t + "\n\n" : "") + refs.join(" ");
    var button = form.querySelector(".send");
    button.disabled = true;
    post("send", { text: t })
      .then(function () {
        text.value = "";
        files = [];
        drawFiles();
        grow();
        showError("");
        window.setTimeout(poll, 400);
      })
      .catch(function (err) { showError(err.message); })
      .then(function () { button.disabled = false; text.focus(); });
  };
  form.addEventListener("submit", function (e) { e.preventDefault(); send(); });
  // Enter sends on a computer (Shift+Enter: a new line); on a phone the
  // button does. Not while an input method is composing a word.
  var coarse = window.matchMedia && window.matchMedia("(pointer: coarse)").matches;
  text.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing && e.keyCode !== 229 && !coarse && slash.hidden) {
      e.preventDefault();
      send();
    }
    if (e.key === "Escape") { slash.hidden = true; menu.hidden = true; }
  });

  var insert = function (s) {
    var at = text.selectionStart || text.value.length;
    var before = text.value.slice(0, at);
    if (before && !/\s$/.test(before)) s = " " + s;
    text.value = before + s + text.value.slice(at);
    text.focus();
    grow();
  };

  // The files as cards: a picture's preview, else its name; × removes
  // one; drag (mouse or finger) to put them in order.
  var drawFiles = function () {
    attached.innerHTML = "";
    files.forEach(function (f, i) {
      var card = document.createElement("div");
      card.className = "att" + (f.preview ? " pic" : "") + (f.error ? " bad" : "");
      card.setAttribute("data-i", i);
      if (f.preview) {
        var img = document.createElement("img");
        img.src = f.preview;
        img.alt = f.name;
        img.draggable = false;
        card.appendChild(img);
      }
      var label = document.createElement("span");
      label.className = "att-name";
      label.textContent = f.error ? f.name + ": " + f.error : (f.path ? f.name : f.name + " …");
      card.appendChild(label);
      var x = document.createElement("button");
      x.type = "button";
      x.className = "att-x";
      x.setAttribute("aria-label", "Remove " + f.name);
      x.textContent = "×";
      x.addEventListener("click", function (e) {
        e.stopPropagation();
        files.splice(files.indexOf(f), 1);
        drawFiles();
      });
      card.appendChild(x);
      f.el = card;
      attached.appendChild(card);
    });
  };

  var dragging = null;
  attached.addEventListener("pointerdown", function (e) {
    var card = e.target.closest(".att");
    if (!card || e.target.closest(".att-x") || files.length < 2) return;
    dragging = { f: files[+card.getAttribute("data-i")], id: e.pointerId };
    card.classList.add("dragging");
    attached.setPointerCapture(e.pointerId);
    e.preventDefault();
  });
  attached.addEventListener("pointermove", function (e) {
    if (!dragging || e.pointerId !== dragging.id) return;
    var over = document.elementFromPoint(e.clientX, e.clientY);
    var card = over && over.closest && over.closest(".att");
    if (!card || card === dragging.f.el) return;
    var target = files[+card.getAttribute("data-i")];
    var r = card.getBoundingClientRect();
    var after = e.clientX > r.left + r.width / 2;
    var from = files.indexOf(dragging.f);
    files.splice(from, 1);
    var at = files.indexOf(target) + (after ? 1 : 0);
    files.splice(at, 0, dragging.f);
    if (at === from) return;
    drawFiles();
    dragging.f.el.classList.add("dragging");
  });
  var drop = function () {
    if (!dragging) return;
    if (dragging.f.el) dragging.f.el.classList.remove("dragging");
    dragging = null;
  };
  attached.addEventListener("pointerup", drop);
  attached.addEventListener("pointercancel", drop);

  var upload = function (blob) {
    var f = { name: blob.name || "pasted.png", path: null, preview: null, error: null };
    files.push(f);
    if (blob.size > 10 * 1024 * 1024) {
      f.error = "over 10 MB";
      drawFiles();
      return;
    }
    drawFiles();
    pending += 1;
    var r = new FileReader();
    r.onload = function () {
      var url = String(r.result);
      if (/^data:image\//.test(url)) { f.preview = url; drawFiles(); }
      post("chat-upload", { filename: f.name, data: url.replace(/^data:[^,]*,/, "") })
        .then(function (j) { f.path = j.data; })
        .catch(function (err) { f.error = err.message; })
        .then(function () { pending -= 1; drawFiles(); });
    };
    r.onerror = function () { pending -= 1; f.error = "could not be read"; drawFiles(); };
    r.readAsDataURL(blob);
  };
  file.addEventListener("change", function () {
    Array.prototype.forEach.call(file.files, upload);
    file.value = "";
  });
  // A picture pasted into the box is uploaded too.
  text.addEventListener("paste", function (e) {
    var files = e.clipboardData && e.clipboardData.files;
    if (files && files.length) {
      e.preventDefault();
      Array.prototype.forEach.call(files, upload);
    }
  });

  plus.addEventListener("click", function () { menu.hidden = !menu.hidden; slash.hidden = true; });
  menu.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    menu.hidden = true;
    if (b.getAttribute("data-act") === "file") file.click();
    else { filterSlash(""); slash.hidden = false; }
  });
  var filterSlash = function (q) {
    var any = false;
    slash.querySelectorAll("li").forEach(function (li) {
      var c = li.querySelector("button").getAttribute("data-cmd");
      var show = c.indexOf("/" + q) === 0 || (q && c.indexOf(q) > 0);
      li.hidden = !show;
      if (show) any = true;
    });
    return any;
  };
  text.addEventListener("input", function () {
    var m = /^\/([^\s]*)$/.exec(text.value);
    slash.hidden = !(m && filterSlash(m[1]));
  });
  slash.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    var c = b.getAttribute("data-cmd") + " ";
    if (/^\/[^\s]*$/.test(text.value) || !text.value) text.value = c;
    else insert(c);
    slash.hidden = true;
    text.focus();
    grow();
  });
  document.addEventListener("click", function (e) {
    if (!form.contains(e.target)) { slash.hidden = true; menu.hidden = true; modelMenu.hidden = true; }
  });

  // Model and effort: sent to the chat as /model and /effort.
  var modelBtn = document.getElementById("model-btn");
  var modelMenu = document.getElementById("model-menu");
  var current = { model: modelBtn.getAttribute("data-model"), effort: modelBtn.getAttribute("data-effort") };
  var markCurrent = function () {
    modelMenu.querySelectorAll("[data-model]").forEach(function (b) {
      b.classList.toggle("on", !!current.model && current.model.indexOf(b.getAttribute("data-model")) >= 0);
    });
    modelMenu.querySelectorAll("[data-effort]").forEach(function (b) {
      b.classList.toggle("on", b.getAttribute("data-effort") === current.effort);
    });
  };
  modelBtn.hidden = false;
  modelBtn.addEventListener("click", function () { modelMenu.hidden = !modelMenu.hidden; menu.hidden = true; slash.hidden = true; markCurrent(); });
  modelMenu.addEventListener("click", function (e) {
    var b = e.target.closest("button[data-send]");
    if (!b) return;
    modelMenu.hidden = true;
    post("send", { text: b.getAttribute("data-send") })
      .then(function () {
        if (b.hasAttribute("data-effort")) current.effort = b.getAttribute("data-effort");
        if (b.hasAttribute("data-model")) {
          current.model = b.getAttribute("data-model");
          modelBtn.textContent = b.textContent + (current.effort ? " · " + current.effort : "");
        } else {
          modelBtn.textContent = modelBtn.textContent.replace(/ · .*$/, "") + " · " + current.effort;
        }
        showError("");
        window.setTimeout(poll, 500);
      })
      .catch(function (err) { showError(err.message); });
  });
  window.btModel = function (j) {
    if (j.model) current.model = j.model;
    if (j.effort) current.effort = j.effort;
    if (j.model_label) modelBtn.textContent = j.model_label + (current.effort ? " · " + current.effort : "");
  };
})();
