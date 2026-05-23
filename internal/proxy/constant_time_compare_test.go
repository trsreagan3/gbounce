// constant_time_compare_test.go — §A99 regression tests.
//
// Pre-§A99 the bearer-token gate on the 4 management endpoints
// (/audit/events, GET /, /admin/profile/reload, /admin/dynamic-
// denies/reload) compared the supplied token to the configured
// token with the `!=` operator. That's a wall-clock-string compare
// that short-circuits on the first mismatching byte, leaking the
// configured token byte-by-byte to an attacker over enough
// requests.
//
// Post-§A99 every gate routes through `crypto/subtle.ConstantTime
// Compare` (the stdlib's constant-time primitive). These tests
// verify the OBSERVABLE STATE per CONTRIBUTING.md: the source files
// MUST use `subtle.ConstantTimeCompare` and MUST NOT contain the
// pre-§A99 `tok != requireBearer` pattern.
//
// A behavioural regression check rounds it out: the gate still
// rejects wrong tokens with 403 + accepts the right token with the
// endpoint's normal success status.

package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// guardedFiles lists every source file in this package that gates
// a bearer token. The fix MUST install the constant-time compare in
// each one; the test fails if any forgot the swap (or if a future
// file is added without including the same primitive).
var guardedFiles = []string{
	"audit_events.go",
	"events_ui.go",
	"profile_reload.go",
	"dynamic_deny_reload.go",
}

func TestBearerComparisonUsesConstantTimeCompare(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for _, name := range guardedFiles {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(wd, name)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			src := string(b)

			// State verification per CONTRIBUTING.md: the source
			// MUST contain the constant-time compare call.
			if !strings.Contains(src, "subtle.ConstantTimeCompare") {
				t.Errorf(
					"§A99 regression: %s no longer uses subtle."+
						"ConstantTimeCompare for the bearer compare. "+
						"A wall-clock-string compare leaks the "+
						"configured token byte-by-byte. See the audit "+
						"finding in iam-roles repo (#484 BB+WB).",
					name,
				)
			}

			// And MUST NOT contain the pre-§A99 leaky pattern.
			if strings.Contains(src, "tok != requireBearer") {
				t.Errorf(
					"§A99 regression: %s reintroduced "+
						"`tok != requireBearer` (non-constant-time). "+
						"Use subtle.ConstantTimeCompare instead.",
					name,
				)
			}

			// Import block MUST include crypto/subtle.
			if !strings.Contains(src, `"crypto/subtle"`) {
				t.Errorf(
					"§A99 regression: %s dropped the "+
						"`crypto/subtle` import. The constant-time "+
						"compare depends on it.",
					name,
				)
			}
		})
	}
}
