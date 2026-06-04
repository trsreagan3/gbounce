package crossbouncer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// QueryOptions controls a cross-bouncer /audit/events fan-out.
type QueryOptions struct {
	Since   string   // short-form (5m/1h/2d/30d/6M/2y) or ISO-8601; "" = no lower bound
	Until   string   // short-form or ISO-8601; "" = no upper bound
	Filters []string // repeatable field=value / field~regex expressions (server-side)
	Limit   int      // per-bouncer cap; <=0 defaults to 1000
	Token   string   // optional bearer token for /audit/events
	Timeout time.Duration
}

const defaultPerBouncerLimit = 1000

// maxPerBouncerLimit mirrors the bouncers' /audit/events AuditEventsMaxLimit.
// A request with limit above this is rejected by the bouncer with HTTP 400,
// so we clamp here — otherwise a caller asking for "lots of events" silently
// gets ZERO from every bouncer (caught dogfooding the compliance overlay).
const maxPerBouncerLimit = 1000

// Querier fans out to bouncer mgmt endpoints. Use NewQuerier; the zero value is
// not ready (it needs an http.Client).
type Querier struct {
	HTTP *http.Client
	now  func() time.Time // injectable for tests
}

// NewQuerier returns a Querier with a sane default client.
func NewQuerier() *Querier {
	return &Querier{
		HTTP: &http.Client{Timeout: 10 * time.Second},
		now:  time.Now,
	}
}

// FetchSessionEvents is the flight-recorder / compliance-map entry point: fan
// out filtered by the cross-bouncer session-id correlation key. Returns the
// merged+sorted events and a per-bouncer notes map ("" = reachable, non-empty
// = error reason) so callers can report coverage gaps honestly.
func (q *Querier) FetchSessionEvents(ctx context.Context, sessionID string, eps []Endpoint, opts QueryOptions) ([]Event, map[string]string) {
	o := opts
	// Canonical long-form filter — matches iam-jit's fanout wire form exactly.
	o.Filters = append([]string{"unmapped.iam_jit.agent.session_id=" + sessionID}, opts.Filters...)
	return q.QueryEvents(ctx, eps, o)
}

// QueryEvents fans out to every endpoint concurrently, merges the NDJSON
// events, stamps each with its source bouncer, and returns them sorted by time
// (events with no parseable timestamp sort last). The notes map always has one
// entry per probed endpoint.
func (q *Querier) QueryEvents(ctx context.Context, eps []Endpoint, opts QueryOptions) ([]Event, map[string]string) {
	if q.now == nil {
		q.now = time.Now
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultPerBouncerLimit
	}
	if limit > maxPerBouncerLimit {
		limit = maxPerBouncerLimit // bouncer rejects limit>cap with HTTP 400
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Build the shared query string once (since/until expanded to absolute).
	qs, err := q.buildQuery(opts, limit)
	if err != nil {
		// A bad time window is a caller error, not a per-bouncer note.
		notes := map[string]string{}
		for _, ep := range eps {
			notes[ep.Name] = "invalid query window: " + err.Error()
		}
		return nil, notes
	}

	type result struct {
		name   string
		events []Event
		note   string
	}
	results := make([]result, len(eps))
	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func(i int, ep Endpoint) {
			defer wg.Done()
			evs, note := q.fetchOne(ctx, ep, qs, opts.Token, timeout)
			results[i] = result{name: ep.Name, events: evs, note: note}
		}(i, ep)
	}
	wg.Wait()

	notes := make(map[string]string, len(eps))
	var merged []Event
	for _, r := range results {
		notes[r.name] = r.note
		merged = append(merged, r.events...)
	}
	sortByTime(merged)
	return merged, notes
}

// fetchOne queries a single bouncer. Any failure becomes a non-empty note
// rather than an error — an unreachable bouncer is a coverage gap, not a fatal.
func (q *Querier) fetchOne(ctx context.Context, ep Endpoint, query, token string, timeout time.Duration) ([]Event, string) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u := strings.TrimRight(ep.MgmtURL, "/") + "/audit/events"
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "bad request: " + err.Error()
	}
	req.Header.Set("Accept", "application/x-ndjson")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := q.HTTP.Do(req)
	if err != nil {
		return nil, "unreachable: " + condense(err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, "unauthorized (set --audit-events-token)"
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	evs, perr := decodeNDJSON(resp.Body, ep.Name)
	if perr != nil {
		return evs, "partial read: " + perr.Error()
	}
	return evs, ""
}

// decodeNDJSON parses one OCSF event per line, stamping _bouncer. Malformed
// lines are skipped (best-effort, like the Python reader). A returned error
// means the stream was truncated; events read so far are still returned.
func decodeNDJSON(r io.Reader, bouncer string) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // allow large event lines
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue // skip malformed line
		}
		if _, ok := m["_bouncer"]; !ok {
			m["_bouncer"] = bouncer // stamp source, matching iam-jit
		}
		out = append(out, Event{Raw: m})
	}
	return out, sc.Err()
}

// buildQuery assembles the /audit/events query string with since/until
// expanded to absolute RFC3339 (gbounce's handler expects RFC3339 bounds).
func (q *Querier) buildQuery(opts QueryOptions, limit int) (string, error) {
	v := url.Values{}
	v.Set("limit", strconv.Itoa(limit))
	if opts.Since != "" {
		t, err := q.expandWindow(opts.Since)
		if err != nil {
			return "", fmt.Errorf("--since %q: %w", opts.Since, err)
		}
		v.Set("since", t.UTC().Format(time.RFC3339))
	}
	if opts.Until != "" {
		t, err := q.expandWindow(opts.Until)
		if err != nil {
			return "", fmt.Errorf("--until %q: %w", opts.Until, err)
		}
		v.Set("until", t.UTC().Format(time.RFC3339))
	}
	// url.Values encodes repeated keys; preserve filter order for determinism.
	enc := v.Encode()
	for _, f := range opts.Filters {
		if f = strings.TrimSpace(f); f != "" {
			enc += "&filter=" + url.QueryEscape(f)
		}
	}
	return enc, nil
}

// expandWindow turns a short-form lookback (5m/1h/2d/30d/6M/2y) into an
// absolute time relative to now, or parses an absolute ISO-8601 timestamp.
func (q *Querier) expandWindow(spec string) (time.Time, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return time.Time{}, fmt.Errorf("empty")
	}
	// Absolute ISO-8601 first.
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, spec); err == nil {
			return t, nil
		}
	}
	// Short-form: <int><unit>. Unit is case-sensitive (m=minute, M=month).
	if len(spec) < 2 {
		return time.Time{}, fmt.Errorf("unrecognized time spec")
	}
	unit := spec[len(spec)-1]
	n, err := strconv.Atoi(spec[:len(spec)-1])
	if err != nil || n < 0 {
		return time.Time{}, fmt.Errorf("unrecognized time spec")
	}
	now := q.now()
	switch unit {
	case 's':
		return now.Add(-time.Duration(n) * time.Second), nil
	case 'm':
		return now.Add(-time.Duration(n) * time.Minute), nil
	case 'h':
		return now.Add(-time.Duration(n) * time.Hour), nil
	case 'd':
		return now.AddDate(0, 0, -n), nil
	case 'w':
		return now.AddDate(0, 0, -7*n), nil
	case 'M':
		return now.AddDate(0, -n, 0), nil
	case 'y':
		return now.AddDate(-n, 0, 0), nil
	}
	return time.Time{}, fmt.Errorf("unknown unit %q", string(unit))
}

// sortByTime orders events ascending by timestamp; events with no parseable
// timestamp sort last (matching the flight-recorder step ordering).
func sortByTime(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		ti, oki := evs[i].TimeMS()
		tj, okj := evs[j].TimeMS()
		if oki != okj {
			return oki // has-timestamp before no-timestamp
		}
		if !oki {
			return false // both missing: keep stable order
		}
		if ti != tj {
			return ti < tj
		}
		return evs[i].Bouncer() < evs[j].Bouncer()
	})
}

// condense trims a verbose error to its first line for a compact note.
func condense(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}
