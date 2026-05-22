package audit

import (
	"testing"
	"time"
)

func TestHTTPMethodToActivityID(t *testing.T) {
	cases := []struct {
		method string
		want   int
	}{
		{"GET", ActivityRead},
		{"get", ActivityRead},
		{"HEAD", ActivityRead},
		{"OPTIONS", ActivityRead},
		{"POST", ActivityCreate},
		{"PUT", ActivityUpdate},
		{"PATCH", ActivityUpdate},
		{"DELETE", ActivityDelete},
		{"CONNECT", ActivityOther},
		{"TRACE", ActivityOther},
		{"", ActivityUnknown},
	}
	for _, c := range cases {
		if got := httpMethodToActivityID(c.method); got != c.want {
			t.Errorf("httpMethodToActivityID(%q) = %d; want %d", c.method, got, c.want)
		}
	}
}

func TestMapHTTPStatusToOCSF(t *testing.T) {
	cases := []struct {
		code   int
		wantID int
	}{
		{0, StatusUnknown},
		{100, StatusSuccess},
		{200, StatusSuccess},
		{204, StatusSuccess},
		{301, StatusSuccess},
		{399, StatusSuccess},
		{400, StatusFailure},
		{403, StatusFailure},
		{404, StatusFailure},
		{499, StatusFailure},
		{500, StatusOther},
		{503, StatusOther},
		{599, StatusOther},
		{999, StatusUnknown},
	}
	for _, c := range cases {
		gotID, _ := mapHTTPStatusToOCSF(c.code)
		if gotID != c.wantID {
			t.Errorf("mapHTTPStatusToOCSF(%d) = %d; want %d", c.code, gotID, c.wantID)
		}
	}
}

func TestFromRequest_FieldShape(t *testing.T) {
	in := RequestInput{
		At:             time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
		DecisionID:     42,
		Mode:           "discovery",
		Method:         "GET",
		Path:           "/v1/dashboards",
		UpstreamHost:   "api.example.com",
		UpstreamPort:   443,
		UpstreamScheme: "https",
		ClientHost:     "127.0.0.1",
		ClientPort:     56000,
		HTTPStatus:     200,
		ResponseSize:   1024,
		LatencyMS:      37,
	}
	ev := FromRequest(in)

	if ev.Metadata.Version != "1.1.0" {
		t.Errorf("metadata.version = %q; want 1.1.0", ev.Metadata.Version)
	}
	if ev.Metadata.Product.Name != "gbounce" {
		t.Errorf("metadata.product.name = %q; want gbounce", ev.Metadata.Product.Name)
	}
	if ev.Metadata.Product.VendorName != "iam-jit" {
		t.Errorf("metadata.product.vendor_name = %q; want iam-jit", ev.Metadata.Product.VendorName)
	}
	if ev.ClassUID != 6003 || ev.CategoryUID != 6 {
		t.Errorf("class/category mismatch: class=%d category=%d", ev.ClassUID, ev.CategoryUID)
	}
	if ev.ActivityID != ActivityRead {
		t.Errorf("activity_id = %d; want %d", ev.ActivityID, ActivityRead)
	}
	if ev.ActivityName != "get" {
		t.Errorf("activity_name = %q; want get", ev.ActivityName)
	}
	if ev.TypeUID != 6003*100+ActivityRead {
		t.Errorf("type_uid = %d; want %d", ev.TypeUID, 6003*100+ActivityRead)
	}
	if ev.StatusID != StatusSuccess {
		t.Errorf("status_id = %d; want %d", ev.StatusID, StatusSuccess)
	}
	if ev.API.Operation != "GET /v1/dashboards" {
		t.Errorf("api.operation = %q; want GET /v1/dashboards", ev.API.Operation)
	}
	if ev.API.Service.Name != "api.example.com" {
		t.Errorf("api.service.name = %q; want api.example.com", ev.API.Service.Name)
	}
	if ev.API.Request.UID != "42" {
		t.Errorf("api.request.uid = %q; want 42", ev.API.Request.UID)
	}
	if len(ev.Resources) != 1 {
		t.Fatalf("resources length = %d; want 1", len(ev.Resources))
	}
	if ev.Resources[0].Name != "/v1/dashboards" {
		t.Errorf("resources[0].name = %q", ev.Resources[0].Name)
	}
	if ev.Resources[0].UID != "https://api.example.com/v1/dashboards" {
		t.Errorf("resources[0].uid = %q", ev.Resources[0].UID)
	}
	if ev.Resources[0].Type != "http resource" {
		t.Errorf("resources[0].type = %q", ev.Resources[0].Type)
	}
	if ev.SrcEndpoint == nil || ev.SrcEndpoint.IP != "127.0.0.1" {
		t.Errorf("src_endpoint = %+v", ev.SrcEndpoint)
	}
	if ev.DstEndpoint == nil || ev.DstEndpoint.Hostname != "api.example.com" || ev.DstEndpoint.Port != 443 {
		t.Errorf("dst_endpoint = %+v", ev.DstEndpoint)
	}
	ext := ev.Unmapped.IAMJIT
	if ext.Verdict != "ALLOW" || ext.Enforced {
		t.Errorf("verdict/enforced = %s/%v; want ALLOW/false", ext.Verdict, ext.Enforced)
	}
	if ext.DecisionID != 42 || ext.Mode != "discovery" {
		t.Errorf("decision_id/mode = %d/%s", ext.DecisionID, ext.Mode)
	}
	if ext.Ext == nil {
		t.Fatal("ext should be populated")
	}
	if ext.Ext["http_status"] != 200 {
		t.Errorf("ext.http_status = %v; want 200", ext.Ext["http_status"])
	}
	if ext.Ext["response_size"] != int64(1024) {
		t.Errorf("ext.response_size = %v; want 1024", ext.Ext["response_size"])
	}
	if ext.Ext["latency_ms"] != int64(37) {
		t.Errorf("ext.latency_ms = %v; want 37", ext.Ext["latency_ms"])
	}
}

func TestFromRequest_DefaultsModeWhenEmpty(t *testing.T) {
	ev := FromRequest(RequestInput{Method: "GET", Path: "/", UpstreamHost: "h"})
	if ev.Unmapped.IAMJIT.Mode != "discovery" {
		t.Errorf("mode default = %q; want discovery", ev.Unmapped.IAMJIT.Mode)
	}
}

func TestFromRequest_HostnameWhenNotIP(t *testing.T) {
	ev := FromRequest(RequestInput{Method: "GET", Path: "/", UpstreamHost: "h", ClientHost: "client.example", ClientPort: 1234})
	if ev.SrcEndpoint == nil || ev.SrcEndpoint.Hostname != "client.example" || ev.SrcEndpoint.IP != "" {
		t.Errorf("src_endpoint = %+v", ev.SrcEndpoint)
	}
}

func TestFromRequest_DELETEMapsToDelete(t *testing.T) {
	ev := FromRequest(RequestInput{Method: "DELETE", Path: "/x", UpstreamHost: "h", HTTPStatus: 204})
	if ev.ActivityID != ActivityDelete {
		t.Errorf("DELETE activity_id = %d", ev.ActivityID)
	}
	if ev.StatusID != StatusSuccess {
		t.Errorf("204 status_id = %d; want %d", ev.StatusID, StatusSuccess)
	}
}

func TestFromRequest_POSTMapsToCreate(t *testing.T) {
	ev := FromRequest(RequestInput{Method: "POST", Path: "/x", UpstreamHost: "h", HTTPStatus: 201})
	if ev.ActivityID != ActivityCreate {
		t.Errorf("POST activity_id = %d", ev.ActivityID)
	}
}

func TestFromRequest_5xxMapsToOther(t *testing.T) {
	ev := FromRequest(RequestInput{Method: "GET", Path: "/x", UpstreamHost: "h", HTTPStatus: 500})
	if ev.StatusID != StatusOther {
		t.Errorf("500 status_id = %d; want %d", ev.StatusID, StatusOther)
	}
}

func TestSetBuildVersion(t *testing.T) {
	old := buildVersion
	defer func() { buildVersion = old }()

	SetBuildVersion("v1.2.3")
	ev := FromRequest(RequestInput{Method: "GET", Path: "/", UpstreamHost: "h"})
	if ev.Metadata.Product.Version != "v1.2.3" {
		t.Errorf("product.version = %q; want v1.2.3", ev.Metadata.Product.Version)
	}

	// Empty value must NOT clobber.
	SetBuildVersion("")
	ev2 := FromRequest(RequestInput{Method: "GET", Path: "/", UpstreamHost: "h"})
	if ev2.Metadata.Product.Version != "v1.2.3" {
		t.Errorf("product.version after empty SetBuildVersion = %q; want v1.2.3", ev2.Metadata.Product.Version)
	}
}

// TestReconstructOverridesFromRow covers the #303 + #305 SQLite-back
// reconstruction logic the proxy + CLI share. Three legs:
//
//   - CONNECT + 502 + ALLOW → #303 dial-failure shape (activity_id=
//     Connect, status_id=Failure, ext.connect_refused=true)
//   - any verdict=DENY → #305 explicit reject (status_id=Denied,
//     ext.deny_reason set)
//   - happy-path (no override conditions) → fields unchanged
func TestReconstructOverridesFromRow(t *testing.T) {
	t.Run("connect failure 303", func(t *testing.T) {
		in := RequestInput{Method: "CONNECT", HTTPStatus: 502, Verdict: "ALLOW"}
		ReconstructOverridesFromRow(&in)
		if in.ActivityIDOverride != ActivityConnect {
			t.Errorf("ActivityIDOverride = %d; want ActivityConnect", in.ActivityIDOverride)
		}
		if in.StatusIDOverride != StatusFailure {
			t.Errorf("StatusIDOverride = %d; want StatusFailure", in.StatusIDOverride)
		}
		if in.ExtraExt["connect_refused"] != true {
			t.Errorf("ExtraExt.connect_refused = %v; want true", in.ExtraExt["connect_refused"])
		}
	})
	t.Run("deny 305", func(t *testing.T) {
		in := RequestInput{Method: "GET", HTTPStatus: 421, Verdict: "DENY"}
		ReconstructOverridesFromRow(&in)
		if in.StatusIDOverride != StatusDenied {
			t.Errorf("StatusIDOverride = %d; want StatusDenied", in.StatusIDOverride)
		}
		got, _ := in.ExtraExt["deny_reason"].(string)
		if got != "non-CONNECT method on CONNECT-only listener" {
			t.Errorf("ExtraExt.deny_reason = %q", got)
		}
	})
	t.Run("connect success — only activity_id lifted", func(t *testing.T) {
		in := RequestInput{Method: "CONNECT", HTTPStatus: 200, Verdict: "ALLOW"}
		ReconstructOverridesFromRow(&in)
		if in.ActivityIDOverride != ActivityConnect {
			t.Errorf("ActivityIDOverride should be ActivityConnect even on success; got %d", in.ActivityIDOverride)
		}
		if in.StatusIDOverride != 0 {
			t.Errorf("StatusIDOverride should stay 0 on success; got %d", in.StatusIDOverride)
		}
		if in.ExtraExt != nil {
			t.Errorf("ExtraExt should stay nil on success; got %+v", in.ExtraExt)
		}
	})
	t.Run("happy-path GET — no overrides", func(t *testing.T) {
		in := RequestInput{Method: "GET", HTTPStatus: 200, Verdict: "ALLOW"}
		ReconstructOverridesFromRow(&in)
		if in.ActivityIDOverride != 0 || in.StatusIDOverride != 0 || in.ExtraExt != nil {
			t.Errorf("happy-path GET should not produce overrides; got %+v", in)
		}
	})
	t.Run("idempotent — preserves caller-provided ext keys", func(t *testing.T) {
		in := RequestInput{
			Method: "CONNECT", HTTPStatus: 502, Verdict: "ALLOW",
			ExtraExt: map[string]any{"connect_refused": false, "x": "y"},
		}
		ReconstructOverridesFromRow(&in)
		// Caller-provided false stays false — the reconstruction must
		// not clobber an explicit value.
		if in.ExtraExt["connect_refused"] != false {
			t.Errorf("connect_refused should be preserved as false; got %v", in.ExtraExt["connect_refused"])
		}
		if in.ExtraExt["x"] != "y" {
			t.Errorf("unrelated ext keys should be preserved; got %v", in.ExtraExt["x"])
		}
	})
	t.Run("nil safe", func(t *testing.T) {
		ReconstructOverridesFromRow(nil) // must not panic
	})
}

func TestLooksLikeIP(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":    true,
		"10.0.0.1":     true,
		"255.255.255.0": true,
		"":             false,
		"localhost":    false,
		"1.2.3":        false,
		"1.2.3.4.5":    false,
		"a.b.c.d":      false,
		"1.2.3.x":      false,
		"1234.0.0.0":   false,
	}
	for in, want := range cases {
		if got := looksLikeIP(in); got != want {
			t.Errorf("looksLikeIP(%q) = %v; want %v", in, got, want)
		}
	}
}
