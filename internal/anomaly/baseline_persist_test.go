package anomaly

import (
	"path/filepath"
	"testing"
	"time"
)

// TestBaselinePersistRoundTrip is the regression for the dogfood finding that
// gbounce's anomaly baseline was in-memory only (reset every restart). Save +
// reload must preserve the learned observations so the detector matures across
// restarts.
func TestBaselinePersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")

	s, err := NewBaselineStoreFromFile(path, 0, 0)
	if err != nil {
		t.Fatalf("new from file: %v", err)
	}
	if s.PersistPath() != path {
		t.Errorf("persistPath=%q", s.PersistPath())
	}
	if st := s.Status(); st["in_memory"] != false || st["persisted"] != true {
		t.Errorf("status should report persisted: %v", st)
	}

	// recent timestamps so the 14-day window doesn't prune them on insert
	base := time.Now().Unix() - 600
	for i := 0; i < 5; i++ {
		s.Observe("agent-a", "s3:GetObject", "arn:aws:s3:::bucket/key", base+int64(i*60))
	}
	s.Observe("agent-b", "http:GET", "api.github.com", base)
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Reload into a fresh store from the same file.
	s2, err := NewBaselineStoreFromFile(path, 0, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	st := s2.Status()
	if st["total_observations"].(int) != 6 {
		t.Errorf("total_observations after reload = %v; want 6", st["total_observations"])
	}
	if st["tracked_keys"].(int) != 2 {
		t.Errorf("tracked_keys after reload = %v; want 2", st["tracked_keys"])
	}
	if st["known_agent_count"].(int) != 2 {
		t.Errorf("known_agent_count after reload = %v; want 2", st["known_agent_count"])
	}
}

func TestNewBaselineStoreFromFile_MissingIsFresh(t *testing.T) {
	s, err := NewBaselineStoreFromFile(filepath.Join(t.TempDir(), "nope.json"), 0, 0)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if s.Status()["total_observations"].(int) != 0 {
		t.Errorf("fresh store should have 0 observations")
	}
}

func TestBaselineStore_NoPathIsInMemory(t *testing.T) {
	s := NewBaselineStore(0, 0)
	if s.Status()["in_memory"] != true || s.Status()["persisted"] != false {
		t.Errorf("no-path store must report in_memory")
	}
	if err := s.Save(); err != nil { // no-op, no error
		t.Errorf("Save with no path should be a no-op: %v", err)
	}
}
