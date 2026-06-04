package mitm

import (
	"net/http"
	"strings"
	"testing"
)

// TestMITM_BodyRedactionMasksAuthorizationHeader (spec test): the
// Authorization header value is replaced with the sentinel string.
func TestMITM_BodyRedactionMasksAuthorizationHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-secret-xyz")
	h.Set("Accept", "application/json")
	out := RedactHeaders(h)
	if got := out.Get("Authorization"); got != RedactedValue {
		t.Errorf("Authorization=%q; want %q", got, RedactedValue)
	}
	if got := out.Get("Accept"); got != "application/json" {
		t.Errorf("Accept=%q; want application/json", got)
	}
	// Ensure secret never appears in the redacted form.
	if strings.Contains(out.Get("Authorization"), "sk-secret-xyz") {
		t.Errorf("secret leaked into redacted output")
	}
}

// TestMITM_BodyRedactionMasksXAPIKey (spec test): vendor-specific
// API key headers are also redacted.
func TestMITM_BodyRedactionMasksXAPIKey(t *testing.T) {
	cases := []string{
		"x-api-key",
		"X-API-Key",
		"x-openai-api-key",
		"X-Anthropic-Api-Key",
		"x-aws-access-key-id",
		"x-vercel-protection-bypass",
	}
	for _, name := range cases {
		h := http.Header{}
		h.Set(name, "secret-value-12345")
		out := RedactHeaders(h)
		if got := out.Get(name); got != RedactedValue {
			t.Errorf("%s=%q; want %q", name, got, RedactedValue)
		}
	}
}

// TestMITM_BodyRedactionMasksJSONApiKeyField (spec test): JSON body
// fields named `api_key` / `token` / `*_secret` get their VALUES
// rewritten to the redaction sentinel; non-credential fields are
// preserved.
func TestMITM_BodyRedactionMasksJSONApiKeyField(t *testing.T) {
	body := []byte(`{
		"user": "alice",
		"api_key": "sk-redactme",
		"refresh_token": "rt-redactme",
		"password": "redactme",
		"nested": {"client_secret": "cs-redactme", "ok": "keep"},
		"signing_key": "kk-redactme"
	}`)
	redacted, changed := RedactJSONBody(body)
	if !changed {
		t.Fatalf("expected changed=true")
	}
	s := string(redacted)
	for _, leaked := range []string{"sk-redactme", "rt-redactme", "cs-redactme", "kk-redactme"} {
		if strings.Contains(s, leaked) {
			t.Errorf("leaked %q in redacted body: %s", leaked, s)
		}
	}
	if !strings.Contains(s, `"user":"alice"`) {
		t.Errorf("user field lost: %s", s)
	}
	if !strings.Contains(s, `"ok":"keep"`) {
		t.Errorf("nested non-credential lost: %s", s)
	}
	if !strings.Contains(s, RedactedValue) {
		t.Errorf("missing sentinel: %s", s)
	}
}

// TestRedactJSONBody_NonJSONUnchanged ensures non-JSON input is
// returned unchanged + changed=false.
func TestRedactJSONBody_NonJSONUnchanged(t *testing.T) {
	body := []byte("plaintext password=hunter2 not JSON")
	out, changed := RedactJSONBody(body)
	if changed {
		t.Errorf("non-JSON marked as changed")
	}
	if string(out) != string(body) {
		t.Errorf("non-JSON body mutated")
	}
}

// TestRedactQueryParams_SecretsStripped covers the URL-level redaction
// (used for url_query in the MITM audit event).
func TestRedactQueryParams_SecretsStripped(t *testing.T) {
	cases := []struct {
		in     string
		expect string
	}{
		{"secret=abc123&user=alice", "secret=" + RedactedValue + "&user=alice"},
		{"token=xyz&page=2", "token=" + RedactedValue + "&page=2"},
		{"api_key=xyz", "api_key=" + RedactedValue},
		{"page=1", "page=1"}, // nothing to redact
	}
	for _, c := range cases {
		out, _ := RedactQueryParams(c.in)
		if out != c.expect {
			t.Errorf("RedactQueryParams(%q) = %q; want %q", c.in, out, c.expect)
		}
	}
}

// TestRedactBody_FormEncodedCredentialsStripped is the NUC-C regression:
// form-encoded bodies previously leaked credentials verbatim because only
// JSON bodies were redacted. RedactBody must strip credential-shape k=v pairs.
func TestRedactBody_FormEncodedCredentialsStripped(t *testing.T) {
	body := []byte("ssn=123-45-6789&password=hunter2&api_key=sk-secret&email=a@b.com")
	out, changed := RedactBody("application/x-www-form-urlencoded", body)
	if !changed {
		t.Fatalf("form body with credentials not marked changed")
	}
	s := string(out)
	if strings.Contains(s, "hunter2") {
		t.Errorf("password value LEAKED in form body: %q", s)
	}
	if strings.Contains(s, "sk-secret") {
		t.Errorf("api_key value LEAKED in form body: %q", s)
	}
	// Non-credential fields preserved (PII redaction is out of scope / BETA).
	if !strings.Contains(s, "ssn=123-45-6789") {
		t.Errorf("non-credential field unexpectedly altered: %q", s)
	}
	// Charset param in Content-Type must not defeat detection.
	out2, changed2 := RedactBody("application/x-www-form-urlencoded; charset=utf-8", body)
	if !changed2 || strings.Contains(string(out2), "hunter2") {
		t.Errorf("charset-suffixed content-type not handled: %q", out2)
	}
}

// TestRedactBody_JSONStillRedacted confirms the JSON path is unchanged.
func TestRedactBody_JSONStillRedacted(t *testing.T) {
	out, changed := RedactBody("application/json", []byte(`{"password":"hunter2","x":1}`))
	if !changed || strings.Contains(string(out), "hunter2") {
		t.Errorf("JSON body password not redacted: %q", out)
	}
}

// TestIsRedactedHeader_KnownNames sanity-checks the known list.
func TestIsRedactedHeader_KnownNames(t *testing.T) {
	known := []string{
		"Authorization", "authorization", "X-API-Key", "x-anthropic-api-key",
		"Cookie", "Set-Cookie",
	}
	for _, n := range known {
		if !IsRedactedHeader(n) {
			t.Errorf("IsRedactedHeader(%q) = false; want true", n)
		}
	}
	if IsRedactedHeader("X-Request-Id") {
		t.Errorf("non-credential header marked as redacted")
	}
}
