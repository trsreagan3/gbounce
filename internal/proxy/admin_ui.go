// admin_ui.go ships the purpose-driven monitoring UI at GET /admin/ui
// (iam-jit #682). Distinct from the legacy live-tail at GET /:
//
//   - GET /        — minimal long-poll audit table (kept for backcompat)
//   - GET /admin/ui — the 5-panel operator console
//     (live stream + stuck signals + denies + features-on/off
//      + features-working honesty surface)
//
// Both pages live on the gbounce mgmt port; both bundle their HTML +
// CSS + JS as a Go string constant so the binary has zero on-disk
// or network dependencies (no CDNs, no fonts, no analytics) per the
// founder direction in [[gbounce-ui-purpose-driven]].
//
// The page consumes the SSE stream at /admin/stream which pushes:
//
//   - event: features        — full feature-status snapshot
//   - event: stuck-signals   — pattern-detected stuck signals
//   - event: decision        — newest audit rows
//
// Auth: same model as /audit/events — loopback no header, external
// bind takes a bearer via #token=... URL fragment surfaced by JS.
package proxy

import (
	"crypto/subtle"
	"html"
	"net/http"
	"strings"
)

// adminUIHandler serves GET /admin/ui — the purpose-driven monitoring
// console.
func adminUIHandler(requireBearer string) http.HandlerFunc {
	body := strings.ReplaceAll(adminUITemplate, "{{BOUNCER_NAME}}",
		html.EscapeString("gbounce"))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "only GET is supported", http.StatusMethodNotAllowed)
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah != "" {
				tok, ok := parseBearer(ah)
				if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(requireBearer)) != 1 {
					http.Error(w, "bearer token rejected", http.StatusForbidden)
					return
				}
			}
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"form-action 'none'")
		_, _ = w.Write([]byte(body))
	}
}

// adminUITemplate is the embedded HTML+CSS+JS for /admin/ui.
//
// Layout (mobile-first; flexbox/grid stack at narrow widths):
//
//	┌────────────────────────────────────────────────────────────┐
//	│ header: status dot + bouncer + monitoring-since            │
//	├────────────────────────────────────────────────────────────┤
//	│ Question 2  — Stuck signals (panel; hidden when empty)     │
//	├──────────────────────┬─────────────────────────────────────┤
//	│ Question 1           │ Question 4+5 (Features)              │
//	│ Live decision stream │ Feature on/off + last-fired + count  │
//	│ (newest at top)      │ + "configured but never fired" pill  │
//	│                      │                                      │
//	├──────────────────────┴─────────────────────────────────────┤
//	│ Question 3 — Recent denies (deny-only filtered stream)     │
//	└────────────────────────────────────────────────────────────┘
const adminUITemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{BOUNCER_NAME}} - monitoring console</title>
<style>
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --panel-2: #1c232c;
  --line: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --allow: #2ea043;
  --deny: #f85149;
  --admin: #58a6ff;
  --warn: #d29922;
  --accent: #f0883e;
  --gap-pill: #8b949e;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font: 13px/1.45 ui-monospace, SFMono-Regular, "SF Mono", Menlo,
        Consolas, "Liberation Mono", monospace;
}
a { color: var(--admin); text-decoration: none; }
a:hover { text-decoration: underline; }
header.appbar {
  display: flex; flex-wrap: wrap; gap: 10px 18px;
  align-items: center; padding: 10px 14px;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  position: sticky; top: 0; z-index: 10;
}
header.appbar .brand {
  font-weight: 700; font-size: 15px; letter-spacing: 0.3px;
}
header.appbar .brand .dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 6px; vertical-align: middle;
  background: var(--allow); box-shadow: 0 0 6px var(--allow);
}
header.appbar .brand .dot.stale { background: var(--warn); box-shadow: 0 0 6px var(--warn); }
header.appbar .brand .dot.err { background: var(--deny); box-shadow: 0 0 6px var(--deny); }
header.appbar .since { color: var(--muted); font-size: 11px; }
header.appbar nav { margin-left: auto; display: flex; gap: 10px; flex-wrap: wrap; }
header.appbar nav a { color: var(--muted); font-size: 11px; }
header.appbar nav a:hover { color: var(--accent); }
.err-banner {
  padding: 8px 14px; background: rgba(248, 81, 73, 0.12);
  border-bottom: 1px solid var(--deny); color: var(--deny); font-size: 12px;
}
.err-banner:empty { display: none; }
.empty-state {
  padding: 10px 14px; background: rgba(208, 153, 34, 0.08);
  border-bottom: 1px solid var(--warn); color: var(--warn); font-size: 12px;
}
.empty-state code {
  background: var(--bg); padding: 1px 4px; border-radius: 3px;
  border: 1px solid var(--line); color: var(--text);
}
main {
  display: grid; grid-template-columns: 1fr; gap: 12px;
  padding: 12px;
}
@media (min-width: 960px) {
  main { grid-template-columns: 3fr 2fr; }
  main .stuck-panel, main .denies-panel { grid-column: 1 / -1; }
}
section.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 6px; overflow: hidden;
}
section.panel header {
  padding: 8px 12px; background: var(--panel-2);
  border-bottom: 1px solid var(--line);
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
}
section.panel header h2 {
  font-size: 12px; letter-spacing: 0.4px; text-transform: uppercase;
  margin: 0; font-weight: 700; color: var(--text);
}
section.panel header .q {
  font-size: 10px; letter-spacing: 0.5px; text-transform: uppercase;
  background: rgba(88, 166, 255, 0.18); color: var(--admin);
  padding: 1px 6px; border-radius: 3px;
}
section.panel header .meta { color: var(--muted); font-size: 11px; margin-left: auto; }
section.panel .body { max-height: 460px; overflow: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
thead th {
  text-align: left; font-weight: 600; background: var(--panel-2); color: var(--muted);
  border-bottom: 1px solid var(--line);
  padding: 5px 10px;
  letter-spacing: 0.4px; text-transform: uppercase; font-size: 11px;
  position: sticky; top: 0;
}
tbody tr { border-bottom: 1px solid #1d232b; }
tbody tr:hover { background: #1a2029; }
tbody td { padding: 5px 10px; vertical-align: top; word-break: break-word; }
.verdict {
  display: inline-block; padding: 1px 7px; border-radius: 3px;
  font-weight: 700; font-size: 11px; letter-spacing: 0.5px;
  border: 1px solid transparent;
}
.verdict.allow { color: var(--allow); border-color: var(--allow); }
.verdict.deny { color: var(--deny); border-color: var(--deny); }
.verdict.admin { color: var(--admin); border-color: var(--admin); }
.verdict.unknown { color: var(--muted); border-color: var(--muted); }
tr.row-deny td { background: rgba(248, 81, 73, 0.05); }
.empty { padding: 24px 14px; text-align: center; color: var(--muted); font-size: 12px; }
.pill {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 10px; letter-spacing: 0.4px; text-transform: uppercase;
  font-weight: 700; border: 1px solid;
}
.pill.on    { color: var(--allow); border-color: var(--allow); }
.pill.off   { color: var(--muted); border-color: var(--muted); }
.pill.gap   { color: var(--warn); border-color: var(--warn);
              background: rgba(208, 153, 34, 0.12); }
.pill.crit  { color: var(--deny); border-color: var(--deny);
              background: rgba(248, 81, 73, 0.12); }
.feature {
  padding: 10px 12px; border-bottom: 1px solid #1d232b;
  display: grid; grid-template-columns: 1fr auto; gap: 4px 12px;
  align-items: baseline;
}
.feature:last-child { border-bottom: none; }
.feature .name { font-weight: 700; color: var(--text); }
.feature .why  { color: var(--muted); font-size: 11px;
                 grid-column: 1 / -1; line-height: 1.5; }
.feature .why code {
  background: var(--bg); padding: 1px 4px; border-radius: 3px;
  border: 1px solid var(--line); color: var(--text);
}
.feature .stats { color: var(--muted); font-size: 11px; }
.feature .stats b { color: var(--text); }
.feature.gap { background: rgba(208, 153, 34, 0.04); }
.feature .err { color: var(--deny); font-size: 11px; grid-column: 1 / -1; }
.stuck-row {
  padding: 10px 12px; border-bottom: 1px solid #1d232b;
}
.stuck-row:last-child { border-bottom: none; }
.stuck-row .sev { font-size: 11px; font-weight: 700; }
.stuck-row .sev.Critical { color: var(--deny); }
.stuck-row .sev.High { color: var(--accent); }
.stuck-row .sev.Medium { color: var(--warn); }
.stuck-row .summary { color: var(--text); font-size: 13px; margin-top: 2px; }
.stuck-row .thresh  { color: var(--muted); font-size: 11px; margin-top: 2px; }
footer {
  padding: 10px 14px; color: var(--muted); font-size: 11px;
  border-top: 1px solid var(--line); text-align: center;
}
</style>
</head>
<body>
<header class="appbar">
  <div class="brand">
    <span class="dot" id="status-dot"></span>{{BOUNCER_NAME}}
    <span style="color: var(--muted); font-weight: 400;"> - monitoring console</span>
  </div>
  <span class="since" id="since-label">monitoring since &mdash;</span>
  <nav>
    <a href="/">live tail (legacy)</a>
    <a href="/suite">suite</a>
    <a href="/healthz">/healthz</a>
    <a href="/admin/features">/admin/features</a>
    <a href="/admin/stuck-signals">/admin/stuck-signals</a>
  </nav>
</header>
<div class="err-banner" id="err-banner"></div>
<div class="empty-state" id="empty-state" style="display: none;">
  No traffic observed yet on this bouncer. To send a test request:
  <code>HTTPS_PROXY=http://127.0.0.1:8769 curl https://api.github.com/zen</code>
</div>
<main>

<section class="panel stuck-panel" id="stuck-panel" style="display: none;">
  <header>
    <span class="q">Q2</span>
    <h2>Is the agent stuck?</h2>
    <span class="meta" id="stuck-meta"></span>
  </header>
  <div class="body" id="stuck-body"></div>
</section>

<section class="panel">
  <header>
    <span class="q">Q1</span>
    <h2>What is my agent doing right now?</h2>
    <span class="meta" id="live-meta">waiting for events</span>
  </header>
  <div class="body">
    <table>
      <thead><tr>
        <th style="width: 90px;">time</th>
        <th style="width: 70px;">verdict</th>
        <th>method + path</th>
        <th style="width: 60px;">status</th>
      </tr></thead>
      <tbody id="live-body">
        <tr><td colspan="4" class="empty">waiting for live events&hellip;</td></tr>
      </tbody>
    </table>
  </div>
</section>

<section class="panel">
  <header>
    <span class="q">Q4 + Q5</span>
    <h2>Features &mdash; on, off, and actually firing</h2>
    <span class="meta" id="features-meta"></span>
  </header>
  <div class="body" id="features-body">
    <div class="empty">loading features&hellip;</div>
  </div>
</section>

<section class="panel denies-panel">
  <header>
    <span class="q">Q3</span>
    <h2>What is gbounce blocking?</h2>
    <span class="meta" id="denies-meta">deny stream</span>
  </header>
  <div class="body">
    <table>
      <thead><tr>
        <th style="width: 90px;">time</th>
        <th>method + path</th>
        <th>upstream</th>
        <th style="width: 60px;">status</th>
      </tr></thead>
      <tbody id="denies-body">
        <tr><td colspan="4" class="empty">no denies observed yet</td></tr>
      </tbody>
    </table>
  </div>
</section>

</main>
<footer>
  read-only viewer &middot; data via
  <a href="/admin/stream">/admin/stream</a> (SSE) &middot;
  <a href="https://github.com/trsreagan3/gbounce">github.com/trsreagan3/gbounce</a>
</footer>
<script>
"use strict";
(function () {
  var MAX_LIVE_ROWS = 200;
  var MAX_DENY_ROWS = 100;
  var token = null;
  try {
    var m = window.location.hash.match(/[#&]token=([^&]+)/);
    if (m) { token = decodeURIComponent(m[1]); }
  } catch (e) { /* ignore */ }

  var elDot = document.getElementById("status-dot");
  var elErr = document.getElementById("err-banner");
  var elSince = document.getElementById("since-label");
  var elEmpty = document.getElementById("empty-state");
  var elLiveBody = document.getElementById("live-body");
  var elLiveMeta = document.getElementById("live-meta");
  var elDenyBody = document.getElementById("denies-body");
  var elDenyMeta = document.getElementById("denies-meta");
  var elFeatBody = document.getElementById("features-body");
  var elFeatMeta = document.getElementById("features-meta");
  var elStuckPanel = document.getElementById("stuck-panel");
  var elStuckBody = document.getElementById("stuck-body");
  var elStuckMeta = document.getElementById("stuck-meta");

  var liveCount = 0;
  var denyCount = 0;

  function setErr(msg) { elErr.textContent = msg || ""; }
  function setDot(state) {
    elDot.classList.remove("stale", "err");
    if (state === "stale") elDot.classList.add("stale");
    if (state === "err") elDot.classList.add("err");
  }

  function fmtTime(ms) {
    if (!ms) return "-";
    var d = new Date(ms);
    if (isNaN(d.getTime())) return String(ms);
    var pad = function (n) { return n < 10 ? "0" + n : "" + n; };
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function fmtAgo(ms) {
    if (!ms) return "never";
    var s = Math.floor((Date.now() - ms) / 1000);
    if (s < 0) s = 0;
    if (s < 60) return s + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }
  function escapeHtml(s) {
    if (s == null) return "";
    return String(s).replace(/[&<>"']/g, function (ch) {
      return ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"})[ch];
    });
  }

  function classifyDecision(ev) {
    var v = (ev.verdict || "").toString().toUpperCase();
    if (v === "DENY" || v === "DENIED") return { label: "DENY", cls: "deny" };
    if (v === "ALLOW" || v === "ALLOWED") return { label: "ALLOW", cls: "allow" };
    if (v === "ERROR") return { label: "ERROR", cls: "deny" };
    return { label: v || "-", cls: "unknown" };
  }

  function addLiveRow(ev) {
    var empty = elLiveBody.querySelector(".empty");
    if (empty) elLiveBody.innerHTML = "";
    var v = classifyDecision(ev);
    var tr = document.createElement("tr");
    tr.className = v.cls === "deny" ? "row-deny" : "";
    var path = ev.path || "-";
    var op = (ev.method || "") + " " + path;
    tr.innerHTML = "<td>" + escapeHtml(fmtTime(ev.time_ms)) + "</td>" +
      "<td><span class=\"verdict " + v.cls + "\">" + escapeHtml(v.label) + "</span></td>" +
      "<td>" + escapeHtml(op) + "</td>" +
      "<td>" + escapeHtml(ev.http_status != null ? String(ev.http_status) : "-") + "</td>";
    elLiveBody.insertBefore(tr, elLiveBody.firstChild);
    while (elLiveBody.children.length > MAX_LIVE_ROWS) {
      elLiveBody.removeChild(elLiveBody.lastChild);
    }
    liveCount += 1;
    elLiveMeta.textContent = liveCount + " decision" + (liveCount === 1 ? "" : "s");
    elEmpty.style.display = "none";

    if (v.cls === "deny") {
      var empty2 = elDenyBody.querySelector(".empty");
      if (empty2) elDenyBody.innerHTML = "";
      var dtr = document.createElement("tr");
      dtr.className = "row-deny";
      dtr.innerHTML = "<td>" + escapeHtml(fmtTime(ev.time_ms)) + "</td>" +
        "<td>" + escapeHtml(op) + "</td>" +
        "<td>" + escapeHtml(ev.upstream_host || "-") + "</td>" +
        "<td>" + escapeHtml(ev.http_status != null ? String(ev.http_status) : "-") + "</td>";
      elDenyBody.insertBefore(dtr, elDenyBody.firstChild);
      while (elDenyBody.children.length > MAX_DENY_ROWS) {
        elDenyBody.removeChild(elDenyBody.lastChild);
      }
      denyCount += 1;
      elDenyMeta.textContent = denyCount + " deny" + (denyCount === 1 ? "" : "s");
    }
  }

  function renderFeatures(snap) {
    var since = snap.process_started_unix_ms;
    if (since) {
      var d = new Date(since);
      elSince.textContent = "monitoring since " + d.toLocaleString();
    }
    var feats = snap.features || [];
    if (!feats.length) {
      elFeatBody.innerHTML = "<div class=\"empty\">no features reported</div>";
      return;
    }
    var html = "";
    var gapCount = 0;
    var onCount = 0;
    feats.forEach(function (f) {
      var pill;
      if (!f.enabled) {
        pill = "<span class=\"pill off\">off</span>";
      } else if (f.configured_but_never_fired) {
        pill = "<span class=\"pill gap\">configured / never fired</span>";
        gapCount += 1;
        onCount += 1;
      } else {
        pill = "<span class=\"pill on\">firing</span>";
        onCount += 1;
      }
      var lastFired = f.last_fired_unix_ms
        ? "last fired <b>" + escapeHtml(fmtAgo(f.last_fired_unix_ms)) + "</b>"
        : "<b>never fired</b>";
      var total = "total <b>" + escapeHtml(String(f.fire_count_total || 0)) + "</b>";
      var win24 = "24h <b>" + escapeHtml(String(f.fire_count_24h || 0)) + "</b>";
      var errHtml = f.last_error
        ? "<div class=\"err\">last error: " + escapeHtml(f.last_error) + "</div>"
        : "";
      var why = f.detail_hint
        ? "<div class=\"why\">how to test: <code>" + escapeHtml(f.detail_hint) + "</code></div>"
        : "";
      var cls = f.configured_but_never_fired ? "feature gap" : "feature";
      html += "<div class=\"" + cls + "\">" +
        "<div class=\"name\">" + escapeHtml(f.name) + " " + pill + "</div>" +
        "<div class=\"stats\">" + lastFired + " &middot; " + total + " &middot; " + win24 + "</div>" +
        why + errHtml +
        "</div>";
    });
    elFeatBody.innerHTML = html;
    var bits = [onCount + " on"];
    if (gapCount > 0) bits.push(gapCount + " configured-but-not-firing");
    elFeatMeta.textContent = bits.join(" - ");
  }

  function renderStuckSignals(payload) {
    var signals = (payload && payload.signals) || [];
    if (!signals.length) {
      elStuckPanel.style.display = "none";
      elStuckMeta.textContent = "";
      return;
    }
    elStuckPanel.style.display = "";
    var html = "";
    signals.forEach(function (s) {
      var sev = escapeHtml(s.severity || "Medium");
      html += "<div class=\"stuck-row\">" +
        "<div class=\"sev " + sev + "\">[" + sev + "] " + escapeHtml(s.kind) + "</div>" +
        "<div class=\"summary\">" + escapeHtml(s.summary || "") + "</div>" +
        "<div class=\"thresh\">threshold: " + escapeHtml(s.threshold || "") + "</div>" +
        "</div>";
    });
    elStuckBody.innerHTML = html;
    elStuckMeta.textContent = signals.length + " signal" + (signals.length === 1 ? "" : "s");
  }

  function streamURL() {
    var qs = [];
    if (token) qs.push("_token=" + encodeURIComponent(token));
    return "/admin/stream" + (qs.length ? "?" + qs.join("&") : "");
  }

  // EventSource auto-reconnects on connection drop. We layer our own
  // visibility heartbeat so the dot turns yellow when the server goes
  // quiet for > 30 s.
  var lastEventAt = Date.now();
  setInterval(function () {
    var dt = Date.now() - lastEventAt;
    if (dt > 30000) {
      setDot("stale");
    } else {
      setDot("ok");
    }
  }, 5000);

  function connect() {
    if (!window.EventSource) {
      setErr("This browser does not support EventSource. The console requires SSE.");
      return;
    }
    var src = new EventSource(streamURL());
    src.addEventListener("decision", function (e) {
      try {
        var data = JSON.parse(e.data);
        addLiveRow(data);
        lastEventAt = Date.now();
      } catch (err) { /* ignore */ }
    });
    src.addEventListener("features", function (e) {
      try {
        var data = JSON.parse(e.data);
        renderFeatures(data);
        lastEventAt = Date.now();
        setErr("");
      } catch (err) { /* ignore */ }
    });
    src.addEventListener("stuck-signals", function (e) {
      try {
        var data = JSON.parse(e.data);
        renderStuckSignals(data);
        lastEventAt = Date.now();
      } catch (err) { /* ignore */ }
    });
    src.onerror = function () {
      setDot("err");
      // EventSource auto-reconnects; we just surface the gap.
      if (!token) {
        setErr("Stream connection failed. If bound off-loopback, append #token=YOUR_TOKEN to the URL.");
      } else {
        setErr("Stream connection failed - reconnecting...");
      }
    };
  }

  // Track whether the empty-state copy should show. If 5s after page
  // load nothing has rendered + the audit_log feature shows zero, the
  // banner stays up.
  setTimeout(function () {
    if (liveCount === 0) elEmpty.style.display = "block";
  }, 5000);

  connect();
})();
</script>
</body>
</html>`
