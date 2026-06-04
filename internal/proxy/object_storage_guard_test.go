package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/trsreagan3/gbounce/internal/audit"
	"github.com/trsreagan3/gbounce/internal/store"
)

// TestRecord_ObjectStorageFiresWithoutAuditLogOrRecorder is the regression for
// the silent S3-sink bug found in dogfooding: the recording guard was
// `if s.log != nil || s.recorder != nil`, so a gbounce configured with ONLY
// the object-storage sink (no --audit-log-path, no session recorder) skipped
// the entire record path and shipped NOTHING to the bucket — no error, no log.
// Object storage is a first-class sink and must fire on its own.
func TestRecord_ObjectStorageFiresWithoutAuditLogOrRecorder(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Minimal fake S3 endpoint: 200 for everything so HeadBucket (Start) +
	// any PutObject succeed without real infra.
	fakeS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeS3.Close)

	osw, err := audit.NewObjectStorageWriter(audit.ObjectStorageWriterOptions{
		EndpointURL: fakeS3.URL,
		Bucket:      "b",
		Region:      "us-east-1",
		Credentials: audit.ObjectStorageCredentials{AccessKeyID: "x", SecretAccessKey: "y"},
		Product:     "gbounce",
	})
	if err != nil {
		t.Fatalf("NewObjectStorageWriter: %v", err)
	}
	if err := osw.Start(context.Background()); err != nil {
		t.Fatalf("object-storage Start: %v", err)
	}
	t.Cleanup(osw.Close)

	// log=nil + recorder=nil — the EXACT config that shipped 0 before the fix.
	srv, err := NewServer(Config{
		Host: "127.0.0.1", Port: 0, MgmtHost: "127.0.0.1", MgmtPort: 0,
		AllowConnect: true, ForwardTimeoutSeconds: 2,
	}, st, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.SetObjectStorageWriter(osw)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	srv.record(req, time.Now(), http.StatusOK, 0)

	if got := srv.objectStorageFireCount.Load(); got == 0 {
		t.Fatal("object-storage sink did not fire with log=nil + recorder=nil — " +
			"the recording guard regressed to exclude s.objectStorage (silent S3 drop)")
	}
}
