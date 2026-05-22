// suite_handler_test.go covers the GET /suite Bounce-suite link page
// shipped in #298. The HTML is signage + client-side fetched status
// pills; JS-driven cross-product /healthz polling isn't testable in
// Go unit tests (it lives in the browser). Structural HTML assertions
// here verify the page serves with the right shape, the right
// anchors, and the right CLI footer. The integration test in
// iam-roles (tests/integration/test_suite_page.py) covers the JS
// behaviour end-to-end when Playwright is available; otherwise it
// falls back to the same structural HTML checks shipped here.
//
// Per [[unified-ui-link-page]] the page intentionally does NOT
// aggregate or proxy data — the tests below assert the page is a
// link page (anchors only) and never invents synthesis claims like
// "single pane of glass."
package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestSuiteUI_RendersHTMLAtSuite(t *testing.T) {
	srv := httptest.NewServer(suiteUIHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/suite")
	if err != nil {
		t.Fatalf("GET /suite: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q; want text/html", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(body))), "<!doctype html>") {
		t.Errorf("body does not start with <!doctype html>: %s", string(body[:200]))
	}
}

func TestSuiteUI_TitleSaysDeploymentStatus(t *testing.T) {
	body := suiteGetBody(t)
	// Per [[security-team-positioning-safety-not-surveillance]] the
	// page frames itself as deployment status, NOT monitoring console.
	if !strings.Contains(body, "<title>Bounce suite - deployment status</title>") {
		t.Errorf("title missing 'deployment status'")
	}
	if strings.Contains(strings.ToLower(body), "monitoring console") {
		t.Errorf("forbidden surveillance phrasing: 'monitoring console'")
	}
}

func TestSuiteUI_AnchorsToAllFourBouncerPorts(t *testing.T) {
	body := suiteGetBody(t)
	// The cards are built client-side from PRODUCT_ORDER + DEFAULT_PORTS;
	// the JS string must include each canonical default port so an
	// operator who never opens the configure-ports modal still ends up
	// on the right URL.
	for _, want := range []string{
		"ibounce: 8767",
		"kbouncer: 8766",
		"dbounce: 8768",
		"gbounce: 8769",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("default-port mapping missing: %q", want)
		}
	}
	// The href the card builds is "http://127.0.0.1:" + port + "/".
	// Assert the format-string prefix lives in the page so the JS can
	// build the anchor at runtime.
	if !strings.Contains(body, `"http://127.0.0.1:"`) {
		t.Errorf("card URL builder missing the 127.0.0.1 prefix")
	}
}

func TestSuiteUI_HasCLIFooterHint(t *testing.T) {
	body := suiteGetBody(t)
	// Per the spec the CLI hint is the cross-bouncer investigation
	// command. Assert it's present verbatim so the copy button has the
	// right command to ship.
	want := "iam-jit audit query --filter agent.session_id="
	if !strings.Contains(body, want) {
		t.Errorf("CLI footer hint missing %q", want)
	}
}

func TestSuiteUI_HasCopyButton(t *testing.T) {
	body := suiteGetBody(t)
	if !strings.Contains(body, `id="copy-btn"`) {
		t.Errorf("missing copy button")
	}
	if !strings.Contains(body, `id="cli-cmd"`) {
		t.Errorf("missing CLI command element")
	}
}

func TestSuiteUI_HasConfigurePortsModal(t *testing.T) {
	body := suiteGetBody(t)
	for _, id := range []string{
		`id="configure-ports"`,
		`id="modal-backdrop"`,
		`id="port-ibounce"`,
		`id="port-kbouncer"`,
		`id="port-dbounce"`,
		`id="port-gbounce"`,
	} {
		if !strings.Contains(body, id) {
			t.Errorf("missing modal element: %s", id)
		}
	}
	// localStorage key must match the docs.
	if !strings.Contains(body, `"bounce.suite.ports"`) {
		t.Errorf("localStorage key 'bounce.suite.ports' missing")
	}
}

func TestSuiteUI_HasStatusBannerAndPills(t *testing.T) {
	body := suiteGetBody(t)
	for _, want := range []string{
		`id="banner"`,
		`id="banner-text"`,
		`"pill unreachable"`,
		`all systems healthy`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing status element: %q", want)
		}
	}
}

func TestSuiteUI_NoSinglePaneOfGlassClaim(t *testing.T) {
	// Per [[ibounce-honest-positioning]]: copy says "navigate to your
	// bouncers" — NEVER "single pane of glass."
	body := strings.ToLower(suiteGetBody(t))
	for _, term := range []string{
		"single pane of glass",
		"unified view",
		"central monitoring",
	} {
		if strings.Contains(body, term) {
			t.Errorf("forbidden over-claim in UI copy: %q", term)
		}
	}
}

func TestSuiteUI_SafetyNotSurveillanceLanguage(t *testing.T) {
	body := strings.ToLower(suiteGetBody(t))
	for _, term := range []string{"violation", "infraction", "unauthorized", "surveillance"} {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(term) + `\b`)
		if re.MatchString(body) {
			t.Errorf("forbidden surveillance term in UI: %s", term)
		}
	}
}

func TestSuiteUI_ReadOnlyNoMutatingControls(t *testing.T) {
	body := strings.ToLower(suiteGetBody(t))
	for _, term := range []string{
		"kill session", "revoke session", "delete profile",
		"approve request", "deny request", "pause profile",
		`method="post"`, `method="delete"`, `method="put"`,
	} {
		if strings.Contains(body, term) {
			t.Errorf("mutating control leaked: %s", term)
		}
	}
}

func TestSuiteUI_NoExternalDependencies(t *testing.T) {
	body := strings.ToLower(suiteGetBody(t))
	for _, needle := range []string{
		"googleapis.com", "gstatic.com", "cloudflare", "cdn.",
		"googletagmanager", "google-analytics", "fonts.google",
		"//unpkg.com", "//cdnjs.", "//jsdelivr.",
		"react", "vue.js", "svelte", "angular",
	} {
		if strings.Contains(body, needle) {
			t.Errorf("external/framework dependency leaked: %s", needle)
		}
	}
}

func TestSuiteUI_StrictCSPHeader(t *testing.T) {
	srv := httptest.NewServer(suiteUIHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/suite")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self': %q", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none': %q", csp)
	}
	// The CSP widens connect-src to 127.0.0.1:* + localhost:* so the
	// browser can fetch each bouncer's /healthz; nothing else should
	// be permitted.
	if !strings.Contains(csp, "127.0.0.1") {
		t.Errorf("CSP missing 127.0.0.1 allowlist: %q", csp)
	}
	if strings.Contains(csp, "https://") {
		t.Errorf("CSP allows remote sources: %q", csp)
	}
}

func TestSuiteUI_NonGETMethodNotAllowed(t *testing.T) {
	srv := httptest.NewServer(suiteUIHandler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/suite", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d (want 405)", resp.StatusCode)
	}
}

func TestSuiteUI_RefreshIntervalIs5Seconds(t *testing.T) {
	body := suiteGetBody(t)
	// Per spec the refresh interval is 5 s. Assert the constant so a
	// future drift back to 2 s (matching events_ui.go's POLL_MS)
	// gets caught.
	if !strings.Contains(body, "REFRESH_MS = 5000") {
		t.Errorf("REFRESH_MS = 5000 missing")
	}
}

func TestSuiteUI_HTMLUnder800Lines(t *testing.T) {
	body := suiteGetBody(t)
	n := strings.Count(body, "\n") + 1
	// Soft cap higher than events_ui's 500 because the link page
	// carries a configure-ports modal + four cards + banner logic;
	// 800 leaves headroom but still catches accidental bloat.
	if n >= 800 {
		t.Errorf("HTML grew to %d lines (cap 800)", n)
	}
}

func TestSuiteUI_HTMLEscapesBouncerName(t *testing.T) {
	body := renderSuiteUI("<script>alert(1)</script>")
	if strings.Contains(body, "<script>alert(1)") {
		t.Errorf("bouncer name not HTML-escaped")
	}
}

// --- helpers ---------------------------------------------------------

func suiteGetBody(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(suiteUIHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/suite")
	if err != nil {
		t.Fatalf("GET /suite: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
