// compliance_dashboard.go — the CSO-facing compliance coverage UI.
//
// GET /compliance/overlay  — fans out to every bouncer's /audit/events over a
//
//	window (all sessions, not one), runs the compliance overlay, returns the
//	framework-coverage JSON.
//
// GET /compliance          — a browser dashboard rendering that coverage:
//
//	per-framework "N of M controls exercised", which controls were touched,
//	which were NOT (honest gap disclosure), and the "evidence on-ramp, NOT a
//	certification" disclaimer.
//
// Built for the CSO / compliance-without-extra-licenses angle: see at a glance
// which framework controls your agents' real activity exercised. gbounce is the
// read-only suite anchor (founder decision 2026-06-04).
package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/trsreagan3/gbounce/internal/compliance"
	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

func complianceOverlayHandler(token string, endpoints []crossbouncer.Endpoint, q crossEventsQuerier) http.HandlerFunc {
	if q == nil {
		q = crossbouncer.NewQuerier()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAuditError(w, http.StatusMethodNotAllowed, "only GET is supported")
			return
		}
		if token != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeAuditError(w, http.StatusUnauthorized, "Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearer(ah)
			if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(token)) != 1 {
				writeAuditError(w, http.StatusForbidden, "bearer token rejected")
				return
			}
		}
		qs := r.URL.Query()
		since := qs.Get("since")
		if since == "" {
			since = "24h"
		}
		framework := qs.Get("framework")
		if framework != "" && !compliance.IsValidFramework(framework) {
			writeAuditError(w, http.StatusBadRequest, "framework must be owasp|mitre|nist|soc2|eu-ai-act")
			return
		}
		events, notes := q.QueryEvents(r.Context(), endpoints, crossbouncer.QueryOptions{
			Since: since, Limit: 5000, Token: token, Timeout: 8 * time.Second,
		})
		res := compliance.BuildOverlay("(recent activity, "+since+")", events, framework, notes)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

func complianceDashboardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAuditError(w, http.StatusMethodNotAllowed, "only GET is supported")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(complianceDashboardHTML))
	}
}

const complianceDashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gbounce — compliance coverage</title>
<style>
  :root { color-scheme: dark; }
  body { font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin:0; background:#0f1115; color:#d8dee9; }
  header { padding:14px 18px; background:#161922; border-bottom:1px solid #2a2f3a; position:sticky; top:0; }
  h1 { font-size:15px; margin:0 0 6px; }
  .controls { display:flex; gap:12px; align-items:center; flex-wrap:wrap; font-size:12px; }
  .controls input { background:#0f1115; color:#d8dee9; border:1px solid #2a2f3a; border-radius:4px; padding:3px 6px; font:inherit; }
  main { padding:18px; max-width:980px; }
  .fw { border:1px solid #2a2f3a; border-radius:8px; margin-bottom:14px; overflow:hidden; }
  .fw h2 { font-size:14px; margin:0; padding:10px 14px; background:#161922; display:flex; justify-content:space-between; align-items:center; }
  .fw h2 .ver { color:#6b7484; font-weight:normal; font-size:12px; }
  .bar { height:8px; background:#1c2029; }
  .bar > span { display:block; height:100%; background:#a3be8c; }
  .fwbody { padding:10px 14px; display:grid; grid-template-columns:1fr 1fr; gap:4px 24px; }
  .ctl { font-size:12px; }
  .touched { color:#a3be8c; }
  .nottouched { color:#5a6373; }
  .count { font-weight:600; }
  .warn { color:#ebcb8b; } .down { color:#bf616a; } .up { color:#a3be8c; }
  #coverage { margin-top:6px; font-size:12px; }
  .disclaimer { margin-top:18px; padding:12px 14px; border:1px dashed #4a3f2a; border-radius:8px; color:#c9b98a; font-size:12px; background:#191712; }
  .empty { color:#6b7484; padding:20px 0; }
</style>
</head>
<body>
<header>
  <h1>compliance coverage <small style="color:#6b7484">— controls your agents' activity exercised (evidence on-ramp)</small></h1>
  <div class="controls">
    <label>window <input id="since" value="24h" size="6"></label>
    <button id="refresh">refresh</button>
    <span id="meta"></span>
  </div>
  <div id="coverage"></div>
</header>
<main>
  <div id="frameworks"></div>
  <div id="disclaimer" class="disclaimer"></div>
</main>
<script>
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
async function load(){
  const since = document.getElementById('since').value.trim() || '24h';
  let d;
  try { const r = await fetch('/compliance/overlay?since=' + encodeURIComponent(since)); d = await r.json(); }
  catch(e){ document.getElementById('coverage').innerHTML = '<span class=down>fetch failed: ' + esc(e.message) + '</span>'; return; }
  document.getElementById('meta').textContent = (d.events_analyzed||0) + ' events analyzed, ' + ((d.overlay||[]).length) + ' tagged';
  const notes = (d.notes||[]);
  document.getElementById('coverage').innerHTML =
    (d.is_partial ? '<b class=warn>PARTIAL</b> &nbsp;' : '<span class=up>complete for the observed window</span> &nbsp;') +
    (notes.length ? '<span class=down>gaps: ' + esc(notes.join('; ')) + '</span>' : '');
  const host = document.getElementById('frameworks'); host.innerHTML = '';
  const cov = d.coverage || [];
  if (!cov.length) { host.innerHTML = '<div class=empty>no coverage data</div>'; }
  for (const fc of cov){
    const pct = fc.controls_in_catalog ? Math.round(100 * fc.controls_touched_count / fc.controls_in_catalog) : 0;
    const el = document.createElement('div'); el.className = 'fw';
    let touched = (fc.controls_touched||[]).map(c =>
      '<div class="ctl touched">✓ ' + esc(c.control) + ' <span style="color:#6b7484">('+c.event_count+'×)</span> ' + esc(c.title) + '</div>').join('');
    let missing = (fc.controls_not_touched||[]).map(c =>
      '<div class="ctl nottouched">· ' + esc(c.control) + ' ' + esc(c.title) + '</div>').join('');
    el.innerHTML =
      '<h2><span>' + esc(fc.name) + ' <span class=ver>' + esc(fc.version) + '</span></span>' +
      '<span class=count>' + fc.controls_touched_count + ' / ' + fc.controls_in_catalog + ' controls</span></h2>' +
      '<div class="bar"><span style="width:' + pct + '%"></span></div>' +
      '<div class="fwbody">' + touched + missing + '</div>';
    host.appendChild(el);
  }
  document.getElementById('disclaimer').textContent = d.disclaimer || '';
}
document.getElementById('refresh').addEventListener('click', load);
document.getElementById('since').addEventListener('keydown', e => { if (e.key === 'Enter') load(); });
load();
</script>
</body>
</html>`
