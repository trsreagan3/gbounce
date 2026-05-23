// mitm_dynamic_deny_test.go — §A28b (#358) coverage.
//
// Pre-§A28b, handleMITMConnect evaluated only s.denyHosts (the static
// `--deny-host` + `--deny-hosts-file` entries). Dynamic-deny rules
// (#324d) silently never fired in MITM mode — a cross-handler
// inconsistency with handleConnect + handleForward, both of which use
// s.effectiveDenyRules().
//
// These tests lock in the fix: the union of static + dynamic deny rules
// applies in MITM mode too, with the same audit-event shape the other
// two handlers produce (recordDenyWithSource → ext.deny_source +
// ext.dynamic_deny_rule_id when applicable).
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/dynamicdeny"
	"github.com/trsreagan3/gbounce/internal/mitm"
	"github.com/trsreagan3/gbounce/internal/store"
)

// startMITMDynamicDenyProxy stands up a MITM-mode proxy with a
// dynamic-deny watcher backed by ddPath. denyHosts is the static
// `--deny-host` list. Returns the proxy addr + the audit log path so
// the test can drive CONNECTs + inspect the OCSF events.
func startMITMDynamicDenyProxy(t *testing.T, denyHosts []string, ddPath string) (proxyAddr, auditPath string) {
	t.Helper()
	dir := t.TempDir()

	// CA + cert minter — same minter shape startMITMTestProxy uses.
	caPaths := mitm.CAPaths{
		Dir:      dir,
		CertFile: filepath.Join(dir, "ca.pem"),
		KeyFile:  filepath.Join(dir, "ca-key.pem"),
	}
	caCert, caKey, err := mitm.GenerateCA(caPaths, false)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	minter, err := mitm.NewCertMinter(caCert, caKey)
	if err != nil {
		t.Fatalf("NewCertMinter: %v", err)
	}

	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	auditPath = filepath.Join(dir, "audit.jsonl")
	lw, err := audit.NewLogWriter(context.Background(), audit.LogWriterOptions{
		Path: auditPath, Fsync: true,
	})
	if err != nil {
		t.Fatalf("NewLogWriter: %v", err)
	}
	t.Cleanup(func() { lw.Close() })

	dw, err := dynamicdeny.NewWatcher(ddPath, nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	dw.SetDebouncePeriod(20 * time.Millisecond)
	if err := dw.Start(context.Background()); err != nil {
		t.Fatalf("watcher.Start: %v", err)
	}
	t.Cleanup(func() { dw.Stop() })

	cfg := Config{
		Host:                  "127.0.0.1",
		Port:                  0,
		MgmtHost:              "127.0.0.1",
		MgmtPort:              0,
		Mode:                  ModeMITM,
		AllowConnect:          true,
		ForwardTimeoutSeconds: 5,
		MITMCertMinter:        minter,
		DenyHosts:             denyHosts,
		DynamicDenyWatcher:    dw,
	}
	srv, err := NewServer(cfg, st, lw, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	proxyL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mgmt: %v", err)
	}
	srv.SetAddrs(proxyL.Addr().String(), mgmtL.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ServeListeners(ctx, proxyL, mgmtL) }()
	t.Cleanup(func() {
		cancel()
		time.Sleep(20 * time.Millisecond)
	})

	healthURL := "http://" + mgmtL.Addr().String() + "/healthz"
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return proxyL.Addr().String(), auditPath
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("MITM proxy never became healthy")
	return
}

// writeMITMDynamicDeniesYAML writes a canonical dynamic-deny single-
// rule YAML at path. applied_to is `[gbounce]` so the gbounce-side
// filter accepts the rule.
const mitmDynamicDenyRuleID = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"

func writeMITMDynamicDeniesYAML(t *testing.T, path, target string) {
	t.Helper()
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + mitmDynamicDenyRuleID,
		`    targets: ["` + target + `"]`,
		`    reason: "mitm dyn deny test"`,
		`    duration: "1h"`,
		`    added_by: "tester@local"`,
		`    added_at: "` + time.Now().UTC().Format(time.RFC3339) + `"`,
		`    applied_to: [gbounce]`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// connectThroughMITMProxy issues a raw HTTP CONNECT through the proxy
// at proxyAddr targeting host:port. Returns the parsed HTTP response
// status — we don't continue the TLS handshake because all we care
// about is the deny verdict that fires BEFORE the hijack.
//
// (Symmetric with connectThroughProxy in deny_hosts_test.go — kept
// local to avoid coupling test helpers across files.)
func connectThroughMITMProxy(t *testing.T, proxyAddr, targetHostPort string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		targetHostPort, targetHostPort)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestHandleMITMConnect_DynamicDenyFires — §A28b (#358). With no
// static --deny-host and one dynamic-deny rule matching *.anthropic.com,
// a CONNECT to api.anthropic.com lands as 403. Pre-fix this returned
// 200 Connection established (the dynamic rule never evaluated).
func TestHandleMITMConnect_DynamicDenyFires(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	writeMITMDynamicDeniesYAML(t, ddPath, "*.anthropic.com")

	proxyAddr, _ := startMITMDynamicDenyProxy(t, nil, ddPath)

	// Wait briefly for the watcher's debounce window so the snapshot
	// is populated before we drive the request.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := connectThroughMITMProxy(t, proxyAddr, "api.anthropic.com:443"); got == http.StatusForbidden {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("CONNECT api.anthropic.com never returned 403 in MITM mode (dynamic-deny did not fire)")
}

// TestHandleMITMConnect_StaticDenyStillFires — defensive: the existing
// static --deny-host shape continues to fire in MITM mode after the
// switch to s.effectiveDenyRules(). Pre-fix this also worked (the call
// site iterated s.denyHosts directly); the new call site iterates the
// union which is a superset, so the static rule still matches.
func TestHandleMITMConnect_StaticDenyStillFires(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	// Write an unrelated dynamic-deny so the watcher has SOMETHING to
	// snapshot but it doesn't match our test target.
	writeMITMDynamicDeniesYAML(t, ddPath, "unrelated.example.com")

	proxyAddr, _ := startMITMDynamicDenyProxy(t,
		[]string{"static-evil.example.com"}, ddPath)

	got := connectThroughMITMProxy(t, proxyAddr, "static-evil.example.com:443")
	if got != http.StatusForbidden {
		t.Errorf("static --deny-host in MITM mode: CONNECT static-evil.example.com → %d; want 403", got)
	}
}

// TestHandleMITMConnect_DynamicDenyAuditShapeMatchesOtherHandlers —
// §A28b (#358). A dynamic-deny match in MITM mode must emit the same
// OCSF ext keys (deny_source + dynamic_deny_rule_id) that handleConnect
// + handleForward emit. SIEM dashboards keyed on those fields must
// see MITM-mode denies as first-class rows.
func TestHandleMITMConnect_DynamicDenyAuditShapeMatchesOtherHandlers(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	writeMITMDynamicDeniesYAML(t, ddPath, "*.anthropic.com")

	proxyAddr, auditPath := startMITMDynamicDenyProxy(t, nil, ddPath)

	// Drive a dynamic-deny CONNECT. Use a poll loop for the watcher
	// debounce window per the prior test.
	deadline := time.Now().Add(500 * time.Millisecond)
	got := 0
	for time.Now().Before(deadline) {
		got = connectThroughMITMProxy(t, proxyAddr, "api.anthropic.com:443")
		if got == http.StatusForbidden {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got != http.StatusForbidden {
		t.Fatalf("dynamic-deny in MITM mode did not fire; got %d", got)
	}

	// Drain the audit log + find the DENY row.
	time.Sleep(120 * time.Millisecond)
	events := readMITMDenyEvents(t, auditPath)
	if len(events) == 0 {
		t.Fatalf("no DENY events landed in audit log %s", auditPath)
	}

	var foundDynamic bool
	for _, ev := range events {
		ext := digMITMEventExt(ev)
		if ext == nil {
			continue
		}
		src, _ := ext["deny_source"].(string)
		rid, _ := ext["dynamic_deny_rule_id"].(string)
		if src == "dynamic" && rid == mitmDynamicDenyRuleID {
			foundDynamic = true
			break
		}
	}
	if !foundDynamic {
		t.Errorf("MITM dynamic-deny audit row missing ext.deny_source=dynamic + ext.dynamic_deny_rule_id=%s",
			mitmDynamicDenyRuleID)
	}
}

// TestHandleMITMConnect_StaticDenyAuditCarriesSourceLabel — confirm
// that a static deny in MITM mode emits ext.deny_source=static
// (the parity field other handlers emit). Defensive — earlier MITM
// code skipped this label entirely; the fix's recordDenyWithSource
// path lands it consistently.
func TestHandleMITMConnect_StaticDenyAuditCarriesSourceLabel(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	writeMITMDynamicDeniesYAML(t, ddPath, "unrelated.example.com")

	proxyAddr, auditPath := startMITMDynamicDenyProxy(t,
		[]string{"static-evil.example.com"}, ddPath)

	if got := connectThroughMITMProxy(t, proxyAddr, "static-evil.example.com:443"); got != http.StatusForbidden {
		t.Fatalf("static deny did not fire in MITM mode: %d", got)
	}
	time.Sleep(120 * time.Millisecond)
	events := readMITMDenyEvents(t, auditPath)
	if len(events) == 0 {
		t.Fatalf("no DENY events in audit log %s", auditPath)
	}
	var found bool
	for _, ev := range events {
		ext := digMITMEventExt(ev)
		if ext == nil {
			continue
		}
		if src, _ := ext["deny_source"].(string); src == "static" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("static deny audit row missing ext.deny_source=static")
	}
}

// readMITMDenyEvents reads the audit JSONL + returns the events whose
// activity_name == CONNECT or whose verdict ext is DENY.
func readMITMDenyEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	var out []map[string]any
	for scanner.Scan() {
		var m map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &m); err == nil {
			ext := digMITMEventExt(m)
			if ext == nil {
				continue
			}
			if _, ok := ext["deny_reason"]; ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func digMITMEventExt(m map[string]any) map[string]any {
	un, _ := m["unmapped"].(map[string]any)
	if un == nil {
		return nil
	}
	jit, _ := un["iam_jit"].(map[string]any)
	if jit == nil {
		return nil
	}
	ext, _ := jit["ext"].(map[string]any)
	return ext
}
