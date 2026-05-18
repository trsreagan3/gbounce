package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAndMigrate(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	// Re-opening the same DB should be a no-op.
	s2, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	s2.Close()
}

func TestRecordAndCountAndRecent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC)
	for i, m := range []string{"GET", "POST", "DELETE"} {
		_, err := s.RecordDecision(DecisionRow{
			At:             now.Add(time.Duration(i) * time.Second),
			Method:         m,
			Path:           "/x",
			UpstreamHost:   "api.example",
			UpstreamPort:   443,
			UpstreamScheme: "https",
			ClientHost:     "127.0.0.1",
			ClientPort:     56000 + i,
			HTTPStatus:     200,
			ResponseSize:   123,
			LatencyMS:      42,
		})
		if err != nil {
			t.Fatalf("RecordDecision[%d]: %v", i, err)
		}
	}
	n, err := s.CountDecisions()
	if err != nil {
		t.Fatalf("CountDecisions: %v", err)
	}
	if n != 3 {
		t.Errorf("CountDecisions = %d; want 3", n)
	}
	got, err := s.RecentDecisions(10)
	if err != nil {
		t.Fatalf("RecentDecisions: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("RecentDecisions len = %d; want 3", len(got))
	}
	// Newest first.
	if got[0].Method != "DELETE" {
		t.Errorf("got[0].Method = %q; want DELETE", got[0].Method)
	}
	if got[0].Verdict != "ALLOW" || got[0].Mode != "discovery" {
		t.Errorf("verdict/mode defaults = %q/%q", got[0].Verdict, got[0].Mode)
	}
}

func TestRecentDecisions_LimitClamping(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	for i := 0; i < 3; i++ {
		if _, err := s.RecordDecision(DecisionRow{Method: "GET", Path: "/", UpstreamHost: "h"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	got, err := s.RecentDecisions(0)
	if err != nil {
		t.Fatalf("RecentDecisions: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("len = %d; want 3", len(got))
	}
}

func TestDefaultDBPathRespectsEnv(t *testing.T) {
	t.Setenv("GBOUNCE_DB", "/tmp/gbounce-env-test.db")
	p, err := DefaultDBPath()
	if err != nil {
		t.Fatalf("DefaultDBPath: %v", err)
	}
	if p != "/tmp/gbounce-env-test.db" {
		t.Errorf("got %q", p)
	}
}
