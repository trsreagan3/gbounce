// Posture tests for gbounce per #383 / §A42.

package posture

import (
	"encoding/json"
	"testing"
)

func TestPosture_ReportsActiveProfileAndMode(t *testing.T) {
	t.Setenv("GBOUNCE_PROFILE", "discovery-only")
	t.Setenv("GBOUNCE_MODE", "discovery")
	b := Capture()
	if b.ActiveProfile != "discovery-only" {
		t.Errorf("ActiveProfile=%q want discovery-only", b.ActiveProfile)
	}
	if b.Mode != "discovery" {
		t.Errorf("Mode=%q want discovery", b.Mode)
	}
	if b.Bouncer != "gbounce" {
		t.Errorf("Bouncer=%q want gbounce", b.Bouncer)
	}
}

func TestPosture_DetectsMisconfigHTTPProxyLoopbackNoListener(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:59734")
	b := Capture()
	// If the test host happens to have something on port 59734 we
	// can't make this assertion; in CI it's nearly always free.
	if b.Misconfig == "" && !b.Running {
		t.Errorf("misconfig should be set when HTTP_PROXY=loopback + port closed")
	}
}

func TestPosture_DefaultPortsArePinned(t *testing.T) {
	if DefaultWirePort != 8080 {
		t.Errorf("DefaultWirePort=%d; update both flag default + this constant", DefaultWirePort)
	}
	if DefaultMgmtPort != 8769 {
		t.Errorf("DefaultMgmtPort=%d; update both flag default + this constant", DefaultMgmtPort)
	}
}

func TestPosture_JSONOutputValidatesAgainstSchema(t *testing.T) {
	b := Capture()
	bs, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(bs, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{
		"schema_version", "bouncer", "captured_at", "running",
		"port", "default_port", "mode", "active_profile",
	} {
		if _, ok := roundtrip[k]; !ok {
			t.Errorf("missing required key %q in JSON output", k)
		}
	}
}

func TestParseLoopbackProxyPort(t *testing.T) {
	cases := map[string]int{
		"http://127.0.0.1:8080":       8080,
		"http://localhost:9999":       9999,
		"http://[::1]:8080":           8080,
		"http://example.com:8080":     0,
		"http://127.0.0.1":            0,
		"":                            0,
		"127.0.0.1:8080":              8080,
		"http://user:pass@127.0.0.1:8080": 8080,
	}
	for in, want := range cases {
		got := parseLoopbackProxyPort(in)
		if got != want {
			t.Errorf("parseLoopbackProxyPort(%q)=%d want %d", in, got, want)
		}
	}
}
