package audit

import (
	"strings"
	"testing"
)

func TestRedactURLPath_NoQueryString(t *testing.T) {
	in := "/v1/dashboards"
	if out := RedactURLPath(in); out != in {
		t.Errorf("RedactURLPath(%q) = %q; want unchanged", in, out)
	}
}

func TestRedactURLPath_EmptyInput(t *testing.T) {
	if out := RedactURLPath(""); out != "" {
		t.Errorf("RedactURLPath(\"\") = %q; want empty", out)
	}
}

func TestRedactURLPath_RedactsSensitiveTokenParam(t *testing.T) {
	in := "/v1/x?token=sentinel-XYZ"
	out := RedactURLPath(in)
	if strings.Contains(out, "sentinel-XYZ") {
		t.Errorf("redaction missed: %q", out)
	}
	if !strings.Contains(out, "token=REDACTED") {
		t.Errorf("expected token=REDACTED in %q", out)
	}
}

func TestRedactURLPath_LeavesBenignParams(t *testing.T) {
	in := "/v1/x?user=alice&page=2&token=secret"
	out := RedactURLPath(in)
	if !strings.Contains(out, "user=alice") || !strings.Contains(out, "page=2") {
		t.Errorf("benign params lost: %q", out)
	}
	if strings.Contains(out, "secret") {
		t.Errorf("secret leaked: %q", out)
	}
}

func TestRedactURLPath_MultipleSensitiveParams(t *testing.T) {
	in := "/v1/x?token=A&api_key=B&authorization=C&bearer=D&secret=E&password=F"
	out := RedactURLPath(in)
	for _, leak := range []string{"=A", "=B", "=C", "=D", "=E", "=F"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in %q", leak, out)
		}
	}
	for _, want := range []string{"token=REDACTED", "api_key=REDACTED", "authorization=REDACTED", "bearer=REDACTED"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestRedactURLPath_CaseInsensitiveKey(t *testing.T) {
	in := "/v1/x?Token=ALPHA&API_KEY=BETA"
	out := RedactURLPath(in)
	if strings.Contains(out, "ALPHA") || strings.Contains(out, "BETA") {
		t.Errorf("case-insensitive denylist missed: %q", out)
	}
}

func TestRedactURLPath_PreservesFragment(t *testing.T) {
	in := "/v1/x?token=secret#section-2"
	out := RedactURLPath(in)
	if !strings.Contains(out, "#section-2") {
		t.Errorf("fragment lost: %q", out)
	}
	if strings.Contains(out, "secret") {
		t.Errorf("secret leaked: %q", out)
	}
}

func TestRedactURLPath_SemicolonSeparator(t *testing.T) {
	in := "/v1/x?token=A;user=alice"
	out := RedactURLPath(in)
	if strings.Contains(out, "=A") {
		t.Errorf("semicolon-separated token leaked: %q", out)
	}
}

func TestRedactEvent_RedactsAllPathBearingFields(t *testing.T) {
	ev := mkEvent("GET", "/v1/x?token=sentinel-XYZ", "api.example.com", 200)
	red := RedactEvent(ev)
	if strings.Contains(red.API.Operation, "sentinel-XYZ") {
		t.Errorf("api.operation leaked: %q", red.API.Operation)
	}
	if len(red.Resources) > 0 {
		if strings.Contains(red.Resources[0].Name, "sentinel-XYZ") {
			t.Errorf("resources[0].name leaked: %q", red.Resources[0].Name)
		}
		if strings.Contains(red.Resources[0].UID, "sentinel-XYZ") {
			t.Errorf("resources[0].uid leaked: %q", red.Resources[0].UID)
		}
	}
	// Original event is untouched (defensive copy semantic).
	if !strings.Contains(ev.Resources[0].Name, "sentinel-XYZ") {
		t.Error("original event was mutated; RedactEvent should clone")
	}
}
