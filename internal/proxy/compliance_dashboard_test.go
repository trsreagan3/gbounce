package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trsreagan3/gbounce/internal/compliance"
	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

func TestComplianceOverlayHandler_MapsRecentActivity(t *testing.T) {
	ib := fakeBouncer(t,
		`{"time":1000,"api":{"operation":"iam:PutRolePolicy"},"unmapped":{"iam_jit":{"verdict":"allow"}}}`,
		`{"time":2000,"api":{"operation":"s3:DeleteBucket"},"unmapped":{"iam_jit":{"verdict":"deny"}}}`,
	)
	endpoints := []crossbouncer.Endpoint{{Name: "ibounce", MgmtURL: ib.URL}}

	h := complianceOverlayHandler("", endpoints, crossbouncer.NewQuerier())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/compliance/overlay?since=1h", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var res compliance.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.EventsAnalyzed != 2 {
		t.Errorf("events_analyzed=%d want 2", res.EventsAnalyzed)
	}
	// 5 frameworks; at least one NIST control touched (deny + priv-esc).
	if len(res.Coverage) != 5 {
		t.Errorf("want 5 frameworks; got %d", len(res.Coverage))
	}
	if res.Disclaimer == "" {
		t.Errorf("disclaimer must be present")
	}
	// honest gap disclosure present per framework
	for _, fc := range res.Coverage {
		if fc.ControlsTouchedCount+len(fc.ControlsNotTouched) != fc.ControlsInCatalog {
			t.Errorf("%s: touched+not_touched != catalog", fc.Framework)
		}
	}
}

func TestComplianceOverlayHandler_RejectsBadFramework(t *testing.T) {
	h := complianceOverlayHandler("", crossbouncer.DefaultEndpoints(false), crossbouncer.NewQuerier())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/compliance/overlay?framework=bogus", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad framework should be 400; got %d", rec.Code)
	}
}

func TestComplianceDashboard_ServesHTML(t *testing.T) {
	srv := httptest.NewServer(complianceDashboardHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	for _, want := range []string{"compliance coverage", "/compliance/overlay", "controls", "disclaimer"} {
		if !strings.Contains(s, want) {
			t.Errorf("dashboard HTML missing %q", want)
		}
	}
}
