// cross_dashboard.go — the cross-bouncer browser dashboard at GET /cross.
//
// A single inline-HTML page (house style, like events_ui.go / admin_ui.go: no
// go:embed, no build step) that polls /cross/events and renders the merged,
// time-ordered stream from every bouncer in the suite, with an honest coverage
// banner (which bouncers answered, which didn't). This is the visible form of
// gbounce-as-suite-anchor: one place to see AWS (ibounce) + HTTP (gbounce) +
// K8s (kbounce) + SQL (dbounce) agent activity together.
package proxy

import "net/http"

// crossDashboardHandler serves the static dashboard HTML. The page fetches
// /cross/events same-origin; on an external bind the operator's reverse proxy
// / token handling applies there (the data endpoint enforces the bearer).
func crossDashboardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAuditError(w, http.StatusMethodNotAllowed, "only GET is supported")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(crossDashboardHTML))
	}
}

const crossDashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gbounce — cross-bouncer view</title>
<style>
  :root { color-scheme: dark; }
  body { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0; background:#0f1115; color:#d8dee9; }
  header { padding:12px 16px; background:#161922; border-bottom:1px solid #2a2f3a; position:sticky; top:0; }
  h1 { font-size:15px; margin:0 0 6px; }
  .controls { display:flex; gap:12px; align-items:center; flex-wrap:wrap; font-size:12px; }
  .controls input { background:#0f1115; color:#d8dee9; border:1px solid #2a2f3a; border-radius:4px; padding:3px 6px; font:inherit; }
  #coverage { margin-top:6px; font-size:12px; }
  .up { color:#a3be8c; } .down { color:#bf616a; } .warn { color:#ebcb8b; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:4px 10px; border-bottom:1px solid #1c2029; vertical-align:top; white-space:nowrap; }
  th { position:sticky; top:64px; background:#161922; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:#8a93a3; }
  td.res, td.reason { white-space:normal; word-break:break-all; max-width:340px; }
  small { color:#6b7484; }
  .v-deny { color:#bf616a; font-weight:600; } .v-allow { color:#a3be8c; } .v-unknown { color:#8a93a3; }
  .proto-AWS { color:#ebcb8b; } .proto-HTTP { color:#88c0d0; } .proto-K8s { color:#b48ead; } .proto-SQL { color:#d08770; }
  .empty { padding:24px 16px; color:#6b7484; }
  tbody tr:hover { background:#161922; }
</style>
</head>
<body>
<header>
  <h1>cross-bouncer view <small>— gbounce suite anchor (read-only)</small></h1>
  <div class="controls">
    <label>since <input id="since" value="15m" size="6"></label>
    <label>session <input id="session" placeholder="(all)" size="20"></label>
    <button id="refresh">refresh</button>
    <label><input type="checkbox" id="auto" checked> auto (3s)</label>
    <span id="count"></span>
  </div>
  <div id="coverage"></div>
</header>
<table>
  <thead><tr><th>time (utc)</th><th>bouncer</th><th>verdict</th><th>action</th><th>principal</th><th>resources</th><th>reason</th></tr></thead>
  <tbody id="rows"></tbody>
</table>
<div id="empty" class="empty" hidden>no events in window</div>
<script>
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtTime(t){ return (t||'').replace('T',' ').replace(/\.\d+Z$/,'').replace('Z',''); }
async function load(){
  const since = document.getElementById('since').value.trim() || '15m';
  const session = document.getElementById('session').value.trim();
  let url = '/cross/events?limit=400&since=' + encodeURIComponent(since);
  if (session) url += '&session=' + encodeURIComponent(session);
  let d;
  try { const r = await fetch(url); d = await r.json(); }
  catch(e){ document.getElementById('coverage').innerHTML = '<span class=down>fetch failed: ' + esc(e.message) + '</span>'; return; }
  const notes = d.coverage || {};
  const parts = Object.keys(notes).sort().map(b => notes[b]
    ? '<span class=down>' + esc(b) + ' ✗ ' + esc(notes[b]) + '</span>'
    : '<span class=up>' + esc(b) + ' ✓</span>');
  document.getElementById('coverage').innerHTML =
    (d.partial ? '<b class=warn>PARTIAL</b> &nbsp;' : '') + 'coverage: ' + parts.join(' &nbsp; ');
  const events = d.events || [];
  document.getElementById('count').textContent = events.length + ' events';
  const tb = document.getElementById('rows'); tb.innerHTML = '';
  document.getElementById('empty').hidden = events.length > 0;
  for (const e of events){
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + esc(fmtTime(e.time)) + '</td>' +
      '<td class="proto-' + esc(e.protocol) + '">' + esc(e.bouncer) + ' <small>' + esc(e.protocol) + '</small></td>' +
      '<td class="v-' + esc(e.verdict||'unknown') + '">' + esc(e.verdict) + '</td>' +
      '<td>' + esc(e.action) + '</td>' +
      '<td>' + esc(e.principal||'') + '</td>' +
      '<td class="res">' + esc((e.resources||[]).join(', ')) + '</td>' +
      '<td class="reason">' + esc(e.reason||'') + '</td>';
    tb.appendChild(tr);
  }
}
document.getElementById('refresh').addEventListener('click', load);
document.getElementById('session').addEventListener('keydown', e => { if (e.key === 'Enter') load(); });
setInterval(() => { if (document.getElementById('auto').checked) load(); }, 3000);
load();
</script>
</body>
</html>`
