package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogWriter_WriteAndReadBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lw, err := NewLogWriter(ctx, LogWriterOptions{Path: path, Fsync: true})
	if err != nil {
		t.Fatalf("NewLogWriter: %v", err)
	}
	ev := FromRequest(RequestInput{
		Method:       "GET",
		Path:         "/v1/x",
		UpstreamHost: "api.example",
		HTTPStatus:   200,
		DecisionID:   7,
	})
	if err := lw.Write(ctx, ev); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Give the worker a moment to drain; then Close blocks until clean.
	time.Sleep(50 * time.Millisecond)
	lw.Close()

	if lw.Total() != 1 {
		t.Errorf("Total = %d; want 1", lw.Total())
	}
	if lw.Dropped() != 0 {
		t.Errorf("Dropped = %d; want 0", lw.Dropped())
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !sc.Scan() {
		t.Fatal("expected at least one line")
	}
	var back Event
	if err := json.Unmarshal(sc.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Metadata.Product.Name != "gbounce" {
		t.Errorf("product = %q", back.Metadata.Product.Name)
	}
	if back.API.Operation != "GET /v1/x" {
		t.Errorf("operation = %q", back.API.Operation)
	}
	if back.Unmapped.IAMJIT.Verdict != "ALLOW" {
		t.Errorf("verdict = %q", back.Unmapped.IAMJIT.Verdict)
	}
}

func TestLogWriter_RequiresPath(t *testing.T) {
	if _, err := NewLogWriter(context.Background(), LogWriterOptions{}); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLogWriter_NilSafe(t *testing.T) {
	var lw *LogWriter
	if err := lw.Write(context.Background(), Event{}); err != nil {
		t.Errorf("nil Write should be no-op; got %v", err)
	}
	lw.Close() // should not panic
	if lw.Total() != 0 || lw.Dropped() != 0 || lw.Path() != "" || lw.LastError() != "" {
		t.Errorf("nil getters should be zero")
	}
}

func TestLogWriter_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	lw, err := NewLogWriter(context.Background(), LogWriterOptions{Path: path})
	if err != nil {
		t.Fatalf("NewLogWriter: %v", err)
	}
	defer lw.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Expect 0600 (mask is umask-affected but 0600 is the most-restrictive
	// we requested; the actual perm should be <= 0600).
	if info.Mode().Perm()&0077 != 0 {
		t.Errorf("audit log file should not be group/world-readable; got %o", info.Mode().Perm())
	}
}
