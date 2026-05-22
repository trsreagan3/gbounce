// audit_events_test.go covers the GET /audit/events handler ships in
// #271. The handler reuses the existing audit-tail filter / OCSF
// builder code, so the tests focus on:
//
//   - request shape (good vs bad query string -> right status code)
//   - filter parity with the CLI (--filter syntax + supported fields)
//   - response shape (NDJSON one-event-per-line vs OCSF Detection
//     Finding bundle)
//   - auth gate (token required when constructed in external-bind mode)
//   - time bounds (since / until ISO 8601)
//   - limit cap (default + explicit + over-max)
//
// The tests serve the handler directly via httptest.NewServer (no
// proxy listener needed) so they're independent of the proxy port's
// bind shape.

package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/store"
)

// seedAuditEventsStore opens a temp store + records a fixed set of
// DecisionRows for the tests. Returns the store; caller defers Close.
func seedAuditEventsStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	base := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	rows := []store.DecisionRow{
		{
			At:             base,
			Method:         "GET",
			Path:           "/v1/users/alice",
			UpstreamHost:   "api.example.com",
			UpstreamPort:   443,
			UpstreamScheme: "https",
			HTTPStatus:     200,
		},
		{
			At:             base.Add(10 * time.Second),
			Method:         "POST",
			Path:           "/v1/orders",
			UpstreamHost:   "api.example.com",
			UpstreamPort:   443,
			UpstreamScheme: "https",
			HTTPStatus:     500,
		},
		{
			At:             base.Add(20 * time.Second),
			Method:         "DELETE",
			Path:           "/v1/users/bob",
			UpstreamHost:   "other.example",
			UpstreamPort:   443,
			UpstreamScheme: "https",
			HTTPStatus:     204,
		},
	}
	for _, r := range rows {
		if _, err := st.RecordDecision(r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	return st
}

// newAuditEventsTestServer wires up the handler + an httptest server
// for the test. requireToken is the bearer token to require (empty =
// loopback shape; no auth gate).
func newAuditEventsTestServer(t *testing.T, requireToken string) (*httptest.Server, *store.Store) {
	t.Helper()
	st := seedAuditEventsStore(t)
	srv := httptest.NewServer(auditEventsHandler(st, requireToken))
	t.Cleanup(srv.Close)
	return srv, st
}

func TestAuditEvents_GetReturnsJSONL(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content-type = %q; want application/x-ndjson", ct)
	}
	// Count lines; we seeded 3 rows.
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("line %d: invalid JSON: %v", n+1, err)
		}
		n++
	}
	if n != 3 {
		t.Errorf("got %d events; want 3", n)
	}
}

func TestAuditEvents_FilterEqMatches(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	// upstream_host filter narrows to the two rows on api.example.com.
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	q.Set("limit", "10")
	q.Add("filter", "upstream_host=api.example.com")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	if n != 2 {
		t.Errorf("got %d events; want 2 (filtered to api.example.com)", n)
	}
}

func TestAuditEvents_BadFilterReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	// Invalid: no operator.
	q.Add("filter", "no_operator_here")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d (want 400)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if !strings.Contains(payload["error"], "filter") {
		t.Errorf("error body = %q; want to mention filter", payload["error"])
	}
}

func TestAuditEvents_LimitCapsResults(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?limit=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	if n != 1 {
		t.Errorf("got %d events; want 1 (capped by limit)", n)
	}
}

func TestAuditEvents_LimitOverMaxRejected(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(fmt.Sprintf("%s?limit=%d", srv.URL, AuditEventsMaxLimit+1))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_SinceUntilBoundsWork(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	// Seeded rows live an hour ago. since=30min-ago, until=now should
	// match none; since=2h-ago, until=now should match all 3.
	noneURL := fmt.Sprintf("%s?since=%s",
		srv.URL,
		url.QueryEscape(time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339)),
	)
	resp, err := http.Get(noneURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	resp.Body.Close()
	if n != 0 {
		t.Errorf("since=30min-ago: got %d events; want 0", n)
	}

	allURL := fmt.Sprintf("%s?since=%s",
		srv.URL,
		url.QueryEscape(time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339)),
	)
	resp2, err := http.Get(allURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp2.Body.Close()
	scanner2 := bufio.NewScanner(resp2.Body)
	n2 := 0
	for scanner2.Scan() {
		n2++
	}
	if n2 != 3 {
		t.Errorf("since=2h-ago: got %d events; want 3", n2)
	}
}

func TestAuditEvents_BadTimeBoundReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?since=not-a-time")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_OCSFBundleFormat(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?format=ocsf-bundle&limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var bundle map[string]any
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatalf("decode bundle: %v\n%s", err, body)
	}
	// Required OCSF Detection Finding fields.
	if cl, _ := bundle["class_uid"].(float64); cl != 2004 {
		t.Errorf("class_uid = %v; want 2004", bundle["class_uid"])
	}
	if cn, _ := bundle["class_name"].(string); cn != "Detection Finding" {
		t.Errorf("class_name = %q; want Detection Finding", cn)
	}
	events, ok := bundle["events"].([]any)
	if !ok {
		t.Fatalf("events not an array; got %T", bundle["events"])
	}
	if len(events) != 3 {
		t.Errorf("bundle events len = %d; want 3", len(events))
	}
}

func TestAuditEvents_UnknownFormatReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?format=wat")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenMissingReturns401(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d (want 401)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenWrongReturns403(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d (want 403)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenCorrectReturns200(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d (want 200)", resp.StatusCode)
	}
}

func TestAuditEvents_NonGETMethodRejected(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	req, _ := http.NewRequest("POST", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d (want 405)", resp.StatusCode)
	}
}

// §A20 (R3-02) — rowsToAuditEvents MUST thread the persisted
// AgentSessionID + AgentName columns from store.DecisionRow into the
// audit.RequestInput it builds. Before the fix the agent fields fell
// on the floor: every event from /audit/events showed
// `agent.name=anonymous` + `detected_from=unknown` even though the
// JSONL log + CLI tail had the correct agent block, breaking cross-
// product `iam-jit audit query --filter agent.session_id=<id>`.
//
// Per [[cross-product-agent-parity]] this matches the dbounce + kbouncer
// recipe: the row carries agent identity; the event must surface it.
func TestRowsToAuditEvents_ThreadsAgentFieldsR302(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows := []store.DecisionRow{
		{
			ID:             7,
			At:             now,
			Method:         "GET",
			Path:           "/v1/widgets",
			UpstreamHost:   "api.example.com",
			UpstreamPort:   443,
			UpstreamScheme: "https",
			HTTPStatus:     200,
			Verdict:        "ALLOW",
			Mode:           "enforce",
			AgentSessionID: "01HXYZ1234567890ABCDEFGHJK",
			AgentName:      "claude-code",
		},
	}
	evs := rowsToAuditEvents(rows)
	if len(evs) != 1 {
		t.Fatalf("got %d events; want 1", len(evs))
	}
	agent := evs[0].Unmapped.IAMJIT.Agent
	if agent == nil {
		t.Fatalf("agent block is nil; want non-nil with name + session id")
	}
	if agent.Name != "claude-code" {
		t.Errorf("agent.Name = %q; want %q", agent.Name, "claude-code")
	}
	if agent.SessionID != "01HXYZ1234567890ABCDEFGHJK" {
		t.Errorf("agent.SessionID = %q; want %q",
			agent.SessionID, "01HXYZ1234567890ABCDEFGHJK")
	}
	if agent.DetectedFrom != "http_header" {
		t.Errorf("agent.DetectedFrom = %q; want %q",
			agent.DetectedFrom, "http_header")
	}
}

// §A20 (R3-02) — empty agent fields on the row MUST still surface as
// the anonymous block (not drop the block entirely). Confirms the
// fallback path: an unattributed row produces
// {name:"anonymous", detected_from:"unknown"} so the SIEM operator
// can query `agent.name=anonymous` to find unattributed traffic.
func TestRowsToAuditEvents_AnonymousWhenNoAgentR302(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows := []store.DecisionRow{
		{
			ID:             8,
			At:             now,
			Method:         "GET",
			Path:           "/v1/healthz",
			UpstreamHost:   "api.example.com",
			UpstreamPort:   443,
			UpstreamScheme: "https",
			HTTPStatus:     200,
			Verdict:        "ALLOW",
			Mode:           "enforce",
			// No agent fields supplied.
		},
	}
	evs := rowsToAuditEvents(rows)
	if len(evs) != 1 {
		t.Fatalf("got %d events; want 1", len(evs))
	}
	agent := evs[0].Unmapped.IAMJIT.Agent
	if agent == nil {
		t.Fatalf("agent block is nil; want non-nil anonymous block")
	}
	if agent.Name != "anonymous" {
		t.Errorf("agent.Name = %q; want %q (anonymous fallback)",
			agent.Name, "anonymous")
	}
	if agent.DetectedFrom != "unknown" {
		t.Errorf("agent.DetectedFrom = %q; want %q",
			agent.DetectedFrom, "unknown")
	}
}

// §A20 (R3-02) — end-to-end: insert a DecisionRow with agent fields,
// hit GET /audit/events, parse the NDJSON response, assert the agent
// block is populated. Catches a refactor where the fields-on-row work
// but the wire format somehow strips them on the way out.
func TestAuditEvents_HTTPSurfaceShowsAgentR302(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	row := store.DecisionRow{
		At:             time.Now().UTC().Add(-30 * time.Second),
		Method:         "GET",
		Path:           "/v1/orders",
		UpstreamHost:   "api.example.com",
		UpstreamPort:   443,
		UpstreamScheme: "https",
		HTTPStatus:     200,
		Verdict:        "ALLOW",
		Mode:           "enforce",
		AgentSessionID: "01HXYZSESSION0000000000000",
		AgentName:      "agent-r302-test",
	}
	if _, err := st.RecordDecision(row); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	srv := httptest.NewServer(auditEventsHandler(st, ""))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "?limit=10")
	if err != nil {
		t.Fatalf("GET /audit/events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 1 {
		t.Fatalf("got %d NDJSON lines; want 1", len(lines))
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("decode event: %v\nraw: %s", err, lines[0])
	}
	unmapped, _ := ev["unmapped"].(map[string]any)
	iamjit, _ := unmapped["iam_jit"].(map[string]any)
	agent, _ := iamjit["agent"].(map[string]any)
	if agent == nil {
		t.Fatalf("agent block missing from event; got: %s", lines[0])
	}
	if name, _ := agent["name"].(string); name != "agent-r302-test" {
		t.Errorf("agent.name = %q; want %q", name, "agent-r302-test")
	}
	if sid, _ := agent["session_id"].(string); sid != "01HXYZSESSION0000000000000" {
		t.Errorf("agent.session_id = %q; want %q",
			sid, "01HXYZSESSION0000000000000")
	}
	if df, _ := agent["detected_from"].(string); df != "http_header" {
		t.Errorf("agent.detected_from = %q; want %q",
			df, "http_header")
	}
}
