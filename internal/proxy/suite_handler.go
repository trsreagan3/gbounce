// suite_handler.go ships the Bounce-suite link page served at
// GET /suite on the gbounce mgmt port alongside /healthz +
// /audit/events + the live audit-stream UI (#298).
//
// SuiteHandler serves the cross-product link page at /suite.
// Per [[unified-ui-link-page]] this is signage + status pills, not
// an aggregator. Bouncers work standalone; this page navigates to them.
//
// All data fetched client-side from each bouncer's /healthz +
// /audit/events. No backend aggregation; no coupling. If the linked
// bouncer is down the card shows a gray "unreachable" pill — the
// suite page itself stays up because it lives in gbounce's mgmt
// server which doesn't depend on any other product being reachable.
//
// Per [[four-products-one-brand]] each bouncer stays autonomous;
// gbounce hosts the link page because it has the richest UI surface
// today (the live audit stream at /), but the page references
// ibounce / kbouncer / dbounce by their own mgmt ports — there is no
// proxying or aggregation happening server-side.
//
// Per [[ibounce-honest-positioning]] copy says "navigate to your
// bouncers" — NEVER "single pane of glass." Status pills are the
// ONLY synthesis on this page; filters, search, and aggregation
// belong to each bouncer's own UI.
//
// Per [[security-team-positioning-safety-not-surveillance]] the page
// frames itself as "deployment status" not "monitoring console."
//
// Customization: the page reads localStorage for operator port
// overrides (key: "bounce.suite.ports"). Defaults match the canonical
// mgmt-port lineage:
//
//	ibounce  8767
//	kbouncer 8766
//	dbounce  8768
//	gbounce  8769
//
// CORS: all bouncer mgmt UIs are on 127.0.0.1 so same-origin policy
// works. NO CORS plumbing needed — both the link page AND the bouncer
// endpoints serve from 127.0.0.1.
//
// Vanilla JS only (no React/Vue/etc.) — keep it dependency-free +
// auditable. Single embedded Go string constant; no build step.
package proxy

import (
	"html"
	"net/http"
	"strings"
)

// renderSuiteUI returns the rendered Bounce-suite link page. The
// bouncerName is HTML-escaped before substitution so an exotic
// product label can never inject script via the page title.
func renderSuiteUI(bouncerName string) string {
	safe := html.EscapeString(bouncerName)
	return strings.ReplaceAll(suiteUITemplate, "{{BOUNCER_NAME}}", safe)
}

// suiteUIHandler builds the http.HandlerFunc for GET /suite. The
// page contains no secrets so we don't require a bearer token even
// when requireBearer is set on the mgmt server — the per-bouncer
// /audit/events fetches the JS makes are subject to each bouncer's
// own auth model (loopback = no header; external = #token=...).
//
// Per [[creates-never-mutates]] the page is read-only — no buttons
// mutate any bouncer's state. The only client-side mutation is
// writing operator port overrides to localStorage.
func suiteUIHandler() http.HandlerFunc {
	body := renderSuiteUI(bouncerNameGbounce)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "only GET is supported", http.StatusMethodNotAllowed)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// CSP mirrors the live-audit UI's (events_ui.go). connect-src
		// stays 'self' because the JS only talks to 127.0.0.1 endpoints
		// — every bouncer mgmt port is same-origin from the browser's
		// perspective (host=127.0.0.1; port differs but is allowed
		// under 'self' for fetch with explicit URLs). Actually,
		// different ports on 127.0.0.1 ARE different origins under
		// the same-origin policy; we widen connect-src to the four
		// canonical mgmt ports so fetch() can hit them. Per
		// [[unified-ui-link-page]] we don't add CORS — the bouncers
		// already serve loopback; we only widen the link page's CSP.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self' http://127.0.0.1:* http://localhost:*; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"form-action 'none'")
		_, _ = w.Write([]byte(body))
	}
}

// suiteUITemplate is the inline HTML page. {{BOUNCER_NAME}} carries
// the hosting product (always "gbounce" today) so the title says
// "served by gbounce" honestly. Under 500 lines per the events_ui
// convention.
const suiteUITemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Bounce suite - deployment status</title>
<style>
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --line: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --healthy: #2ea043;
  --degraded: #d29922;
  --critical: #f85149;
  --unreachable: #6e7681;
  --accent: #f0883e;
  --link: #58a6ff;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.45 ui-monospace, SFMono-Regular, "SF Mono", Menlo,
        Consolas, "Liberation Mono", monospace;
}
header {
  padding: 14px 18px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
}
header h1 { margin: 0 0 4px 0; font-size: 17px; letter-spacing: 0.3px; }
header .sub { color: var(--muted); font-size: 12px; }
.banner {
  margin: 14px 18px 0 18px;
  padding: 10px 14px;
  border-radius: 4px;
  border: 1px solid var(--line);
  background: var(--panel);
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 10px;
}
.banner .dot {
  display: inline-block;
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--unreachable);
}
.banner.healthy { border-color: var(--healthy); }
.banner.healthy .dot { background: var(--healthy); box-shadow: 0 0 6px var(--healthy); }
.banner.degraded { border-color: var(--degraded); }
.banner.degraded .dot { background: var(--degraded); box-shadow: 0 0 6px var(--degraded); }
.banner.critical { border-color: var(--critical); }
.banner.critical .dot { background: var(--critical); box-shadow: 0 0 6px var(--critical); }
main { padding: 18px; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 14px;
}
.card {
  border: 1px solid var(--line);
  border-radius: 5px;
  background: var(--panel);
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.card .name {
  font-size: 16px; font-weight: 700;
  display: flex; align-items: center; gap: 8px;
}
.card .desc { color: var(--muted); font-size: 12px; min-height: 32px; }
.pill {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.4px;
  text-transform: uppercase;
  border: 1px solid var(--unreachable);
  color: var(--unreachable);
}
.pill.healthy { border-color: var(--healthy); color: var(--healthy); }
.pill.degraded { border-color: var(--degraded); color: var(--degraded); }
.pill.critical { border-color: var(--critical); color: var(--critical); }
.pill.unreachable { border-color: var(--unreachable); color: var(--unreachable); }
.stats { color: var(--muted); font-size: 12px; }
.stats b { color: var(--text); }
.card-actions { margin-top: auto; display: flex; gap: 10px; }
.card-actions a {
  color: var(--link);
  text-decoration: none;
  border: 1px solid var(--line);
  padding: 5px 10px;
  border-radius: 4px;
  font-size: 12px;
}
.card-actions a:hover { border-color: var(--accent); color: var(--accent); }
.foot {
  margin: 18px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--panel);
}
.foot .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 6px; }
.foot .cli {
  display: flex;
  align-items: center;
  gap: 10px;
  font-family: ui-monospace, monospace;
  font-size: 13px;
}
.foot code {
  background: var(--bg);
  border: 1px solid var(--line);
  padding: 5px 8px;
  border-radius: 3px;
  flex: 1;
  overflow-x: auto;
  white-space: nowrap;
}
.foot button {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--line);
  padding: 5px 10px;
  border-radius: 4px;
  font: inherit;
  cursor: pointer;
}
.foot button:hover { border-color: var(--accent); }
.config-link {
  margin: 0 18px 18px 18px;
  text-align: right;
  font-size: 12px;
}
.config-link a { color: var(--muted); text-decoration: none; }
.config-link a:hover { color: var(--accent); }
.modal-backdrop {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.6);
  display: none;
  align-items: center; justify-content: center;
  z-index: 100;
}
.modal-backdrop.open { display: flex; }
.modal {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 5px;
  padding: 16px;
  width: 340px;
  max-width: 90vw;
}
.modal h2 { margin: 0 0 10px 0; font-size: 15px; }
.modal .row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.modal .row label { width: 80px; color: var(--muted); font-size: 12px; }
.modal .row input {
  flex: 1;
  background: var(--bg); color: var(--text);
  border: 1px solid var(--line); border-radius: 4px;
  padding: 4px 6px; font: inherit;
}
.modal .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 10px; }
.modal button {
  background: var(--bg); color: var(--text);
  border: 1px solid var(--line); border-radius: 4px;
  padding: 5px 12px; font: inherit; cursor: pointer;
}
.modal button.primary { border-color: var(--accent); color: var(--accent); }
@media (max-width: 600px) {
  .grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<header>
  <h1>Bounce suite - deployment status</h1>
  <div class="sub">served by {{BOUNCER_NAME}} - navigate to your bouncers</div>
</header>
<div class="banner" id="banner">
  <span class="dot"></span>
  <span id="banner-text">checking bouncer health&hellip;</span>
</div>
<main>
<div class="grid" id="grid"></div>
</main>
<div style="max-width:1100px;margin:6px auto 0;padding:0 20px;">
  <div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;">suite-wide views &mdash; gbounce anchor (read-only aggregation)</div>
  <div style="display:flex;gap:12px;flex-wrap:wrap;">
    <a href="/cross" style="background:var(--panel);border:1px solid #2a2f3a;border-radius:8px;padding:10px 14px;text-decoration:none;color:var(--accent);font-size:13px;">cross-bouncer activity &rarr;</a>
    <a href="/compliance" style="background:var(--panel);border:1px solid #2a2f3a;border-radius:8px;padding:10px 14px;text-decoration:none;color:var(--accent);font-size:13px;">compliance coverage &rarr;</a>
  </div>
</div>
<div class="config-link">
  <a href="#" id="configure-ports">configure ports</a>
</div>
<div class="foot">
  <div class="label">cross-bouncer investigation</div>
  <div class="cli">
    <code id="cli-cmd">iam-jit audit query --filter agent.session_id=&lt;UUID&gt;</code>
    <button type="button" id="copy-btn">copy</button>
  </div>
</div>
<div class="modal-backdrop" id="modal-backdrop">
  <div class="modal">
    <h2>configure mgmt ports</h2>
    <div class="row"><label>ibounce</label><input type="number" id="port-ibounce"></div>
    <div class="row"><label>kbouncer</label><input type="number" id="port-kbouncer"></div>
    <div class="row"><label>dbounce</label><input type="number" id="port-dbounce"></div>
    <div class="row"><label>gbounce</label><input type="number" id="port-gbounce"></div>
    <div class="actions">
      <button type="button" id="modal-reset">reset</button>
      <button type="button" id="modal-cancel">cancel</button>
      <button type="button" class="primary" id="modal-save">save</button>
    </div>
  </div>
</div>
<script>
"use strict";
(function () {
  var REFRESH_MS = 5000;
  var STORAGE_KEY = "bounce.suite.ports";
  var DEFAULT_PORTS = {
    ibounce: 8767,
    kbouncer: 8766,
    dbounce: 8768,
    gbounce: 8769
  };
  var PRODUCT_INFO = {
    ibounce: { name: "ibounce", desc: "AWS IAM call audit + profile gate" },
    kbouncer: { name: "kbouncer", desc: "K8s API audit at the cluster edge" },
    dbounce: { name: "dbounce", desc: "Database SQL audit + redaction" },
    gbounce: { name: "gbounce", desc: "Generic HTTP/HTTPS forward proxy audit" }
  };
  var PRODUCT_ORDER = ["ibounce", "kbouncer", "dbounce", "gbounce"];

  function loadPorts() {
    try {
      var raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) return Object.assign({}, DEFAULT_PORTS);
      var parsed = JSON.parse(raw);
      var out = Object.assign({}, DEFAULT_PORTS);
      PRODUCT_ORDER.forEach(function (k) {
        var n = parseInt(parsed[k], 10);
        if (!isNaN(n) && n > 0 && n < 65536) out[k] = n;
      });
      return out;
    } catch (e) {
      return Object.assign({}, DEFAULT_PORTS);
    }
  }

  function savePorts(ports) {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(ports));
    } catch (e) { /* localStorage may be disabled; ignore */ }
  }

  function resetPorts() {
    try { window.localStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
  }

  var ports = loadPorts();

  var elGrid = document.getElementById("grid");
  var elBanner = document.getElementById("banner");
  var elBannerText = document.getElementById("banner-text");
  var cards = {};

  function buildCards() {
    elGrid.innerHTML = "";
    cards = {};
    PRODUCT_ORDER.forEach(function (k) {
      var info = PRODUCT_INFO[k];
      var port = ports[k];
      var url = "http://127.0.0.1:" + port + "/";

      var card = document.createElement("div");
      card.className = "card";

      var name = document.createElement("div");
      name.className = "name";
      var pill = document.createElement("span");
      pill.className = "pill unreachable";
      pill.textContent = "unknown";
      var nameText = document.createElement("span");
      nameText.textContent = info.name;
      name.appendChild(nameText);
      name.appendChild(pill);

      var desc = document.createElement("div");
      desc.className = "desc";
      desc.textContent = info.desc;

      var stats = document.createElement("div");
      stats.className = "stats";
      stats.textContent = "no data yet";

      var actions = document.createElement("div");
      actions.className = "card-actions";
      var openLink = document.createElement("a");
      openLink.href = url;
      openLink.target = "_blank";
      openLink.rel = "noopener noreferrer";
      openLink.textContent = "open ui";
      var portLabel = document.createElement("span");
      portLabel.style.color = "var(--muted)";
      portLabel.style.fontSize = "12px";
      portLabel.style.alignSelf = "center";
      portLabel.textContent = "port " + port;
      actions.appendChild(openLink);
      actions.appendChild(portLabel);

      card.appendChild(name);
      card.appendChild(desc);
      card.appendChild(stats);
      card.appendChild(actions);
      elGrid.appendChild(card);

      cards[k] = { card: card, pill: pill, stats: stats };
    });
  }

  function setPill(el, state, label) {
    el.classList.remove("healthy", "degraded", "critical", "unreachable");
    el.classList.add(state);
    el.textContent = label;
  }

  function fetchOne(key) {
    var port = ports[key];
    var healthUrl = "http://127.0.0.1:" + port + "/healthz";
    var eventsUrl = "http://127.0.0.1:" + port + "/audit/events?limit=1";
    var card = cards[key];
    if (!card) return Promise.resolve({ key: key, state: "unreachable" });

    var ctrl = (typeof AbortController === "function") ? new AbortController() : null;
    var tid = setTimeout(function () { if (ctrl) ctrl.abort(); }, 3000);

    return fetch(healthUrl, { signal: ctrl ? ctrl.signal : undefined, credentials: "omit", mode: "cors" })
      .then(function (resp) {
        clearTimeout(tid);
        if (!resp.ok) {
          setPill(card.pill, "critical", "critical");
          card.stats.textContent = "/healthz returned " + resp.status;
          return { key: key, state: "critical" };
        }
        return resp.json().then(function (body) {
          var state = "healthy";
          var label = "healthy";
          if (body && (body.status === "degraded")) { state = "degraded"; label = "degraded"; }
          else if (body && body.status && body.status !== "ok") { state = "degraded"; label = String(body.status); }
          setPill(card.pill, state, label);
          // Fetch the most recent event for the quick-stats line.
          return fetch(eventsUrl, { credentials: "omit", mode: "cors" })
            .then(function (er) {
              if (!er.ok) {
                card.stats.textContent = "events endpoint returned " + er.status;
                return { key: key, state: state };
              }
              return er.text().then(function (txt) {
                var last = null;
                var lines = (txt || "").split(/\r?\n/);
                for (var i = lines.length - 1; i >= 0; i--) {
                  var ln = lines[i].trim();
                  if (!ln) continue;
                  try { last = JSON.parse(ln); break; } catch (e) { /* skip */ }
                }
                if (last) {
                  var u = (last.unmapped && last.unmapped.iam_jit) || {};
                  var verdict = (u.verdict || last.verdict || "-").toString().toUpperCase();
                  card.stats.textContent = "last verdict: " + verdict;
                } else {
                  card.stats.textContent = "no events yet";
                }
                return { key: key, state: state };
              });
            })
            .catch(function () {
              card.stats.textContent = "events endpoint unreachable";
              return { key: key, state: state };
            });
        });
      })
      .catch(function () {
        clearTimeout(tid);
        setPill(card.pill, "unreachable", "unreachable");
        card.stats.textContent = "bouncer unreachable";
        return { key: key, state: "unreachable" };
      });
  }

  function refreshBanner(results) {
    var healthy = 0, degraded = 0, critical = 0, unreachable = 0;
    results.forEach(function (r) {
      if (r.state === "healthy") healthy += 1;
      else if (r.state === "degraded") degraded += 1;
      else if (r.state === "critical") critical += 1;
      else unreachable += 1;
    });
    elBanner.classList.remove("healthy", "degraded", "critical");
    if (critical > 0) {
      elBanner.classList.add("critical");
      elBannerText.textContent = critical + " bouncer" + (critical === 1 ? "" : "s") + " critical";
    } else if (degraded > 0) {
      elBanner.classList.add("degraded");
      elBannerText.textContent = degraded + " bouncer" + (degraded === 1 ? "" : "s") + " degraded";
    } else if (unreachable > 0) {
      elBanner.classList.add("degraded");
      elBannerText.textContent = unreachable + " bouncer" + (unreachable === 1 ? "" : "s") + " unreachable";
    } else if (healthy === PRODUCT_ORDER.length) {
      elBanner.classList.add("healthy");
      elBannerText.textContent = "all systems healthy";
    } else {
      elBannerText.textContent = "deployment status pending";
    }
  }

  function refresh() {
    var jobs = PRODUCT_ORDER.map(fetchOne);
    Promise.all(jobs).then(refreshBanner);
  }

  buildCards();
  refresh();
  setInterval(refresh, REFRESH_MS);

  // copy button
  var elCopy = document.getElementById("copy-btn");
  var elCmd = document.getElementById("cli-cmd");
  elCopy.addEventListener("click", function () {
    var text = elCmd.textContent || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        elCopy.textContent = "copied";
        setTimeout(function () { elCopy.textContent = "copy"; }, 1500);
      });
    } else {
      // legacy fallback
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        elCopy.textContent = "copied";
        setTimeout(function () { elCopy.textContent = "copy"; }, 1500);
      } catch (e) { /* ignore */ }
    }
  });

  // configure-ports modal
  var elConfigure = document.getElementById("configure-ports");
  var elBackdrop = document.getElementById("modal-backdrop");
  var elInIb = document.getElementById("port-ibounce");
  var elInKb = document.getElementById("port-kbouncer");
  var elInDb = document.getElementById("port-dbounce");
  var elInGb = document.getElementById("port-gbounce");

  function fillModal() {
    elInIb.value = ports.ibounce;
    elInKb.value = ports.kbouncer;
    elInDb.value = ports.dbounce;
    elInGb.value = ports.gbounce;
  }
  elConfigure.addEventListener("click", function (e) {
    e.preventDefault();
    fillModal();
    elBackdrop.classList.add("open");
  });
  document.getElementById("modal-cancel").addEventListener("click", function () {
    elBackdrop.classList.remove("open");
  });
  document.getElementById("modal-reset").addEventListener("click", function () {
    resetPorts();
    ports = loadPorts();
    fillModal();
    buildCards();
    refresh();
    elBackdrop.classList.remove("open");
  });
  document.getElementById("modal-save").addEventListener("click", function () {
    var next = {
      ibounce: parseInt(elInIb.value, 10),
      kbouncer: parseInt(elInKb.value, 10),
      dbounce: parseInt(elInDb.value, 10),
      gbounce: parseInt(elInGb.value, 10)
    };
    var ok = true;
    PRODUCT_ORDER.forEach(function (k) {
      if (isNaN(next[k]) || next[k] <= 0 || next[k] >= 65536) ok = false;
    });
    if (!ok) return;
    savePorts(next);
    ports = next;
    buildCards();
    refresh();
    elBackdrop.classList.remove("open");
  });
})();
</script>
</body>
</html>
`
