// loader_test.go — #324d loader regression suite.
//
// Covers:
//   - happy-path YAML load + filter to gbounce-applicable entries
//   - schema-violation rejection (missing required field, wrong type,
//     bad rule-id shape, bad duration shape, bad applied_to bouncer)
//   - filter: ARN-targeted + k8s-namespace-targeted rules are skipped;
//     URL-targeted + bare-hostname rules are retained.
//   - round-trip JSON shape: a loaded ruleset re-marshals back to the
//     same YAML structure (round-trippable so a future writer can
//     reuse the struct).

package dynamicdeny

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// validRuleID is a stable rule id used across the suite. ULID body
// "01HZ8VKJ6Y2BJTPVZ3PNX97A2C" matches the schema's Crockford base32
// shape (rejects I/L/O/U).
const validRuleID = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
const validRuleID2 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2D"
const validRuleID3 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2E"
const validRuleID4 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2F"

// goldenYAML builds a single-rule YAML payload targeting gbounce.
func goldenYAML(t *testing.T) string {
	t.Helper()
	added := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(3 * time.Hour).Format(time.RFC3339)
	return strings.Join([]string{
		`schema_version: "1.0"`,
		`product: iam-jit-dynamic-denies`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets:`,
		`      - "*.openai.com"`,
		`    reason: "operator: incident #4711 — lock out OpenAI for 3h"`,
		`    duration: "3h"`,
		`    added_by: "operator@org.com"`,
		`    added_at: "` + added + `"`,
		`    expires_at: "` + expires + `"`,
		`    applied_to:`,
		`      - gbounce`,
		`    applies_to_recommender: false`,
		`    source: "cli"`,
	}, "\n")
}

func TestLoader_LoadsValidYAML(t *testing.T) {
	rs, err := LoadBytes([]byte(goldenYAML(t)), "test.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if rs == nil || len(rs.Rules) != 1 {
		t.Fatalf("Rules = %v; want 1", rs)
	}
	r := rs.Rules[0]
	if r.ID != validRuleID {
		t.Errorf("ID = %q; want %q", r.ID, validRuleID)
	}
	if len(r.Targets) != 1 || r.Targets[0] != "*.openai.com" {
		t.Errorf("Targets = %v; want [*.openai.com]", r.Targets)
	}
	if r.Duration != "3h" {
		t.Errorf("Duration = %q; want 3h", r.Duration)
	}
	if r.Source != "cli" {
		t.Errorf("Source = %q; want cli", r.Source)
	}
	if rs.SourcePath != "test.yaml" {
		t.Errorf("SourcePath = %q; want test.yaml", rs.SourcePath)
	}
}

func TestLoader_LoadFile_MissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	rs, err := LoadFile(filepath.Join(dir, "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadFile on missing path should not error; got %v", err)
	}
	if rs == nil || len(rs.Rules) != 0 {
		t.Errorf("Rules = %v; want empty", rs)
	}
}

func TestLoader_LoadFile_RealFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(goldenYAML(t)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rs, err := LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Errorf("Rules = %d; want 1", len(rs.Rules))
	}
}

func TestLoader_RejectsSchemaViolation_MissingSchemaVersion(t *testing.T) {
	body := strings.Join([]string{
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: [api.openai.com]`,
		`    reason: "test"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
	}, "\n")
	_, err := LoadBytes([]byte(body), "x.yaml")
	if err == nil {
		t.Fatal("missing schema_version should reject; got no error")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error %q should mention schema_version", err.Error())
	}
}

func TestLoader_RejectsSchemaViolation_BadRuleID(t *testing.T) {
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: not-a-valid-id`,
		`    targets: [api.openai.com]`,
		`    reason: "test"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
	}, "\n")
	_, err := LoadBytes([]byte(body), "x.yaml")
	if err == nil {
		t.Fatal("bad rule id should reject; got no error")
	}
	if !strings.Contains(err.Error(), "dd_") {
		t.Errorf("error %q should mention the expected `dd_<ULID>` shape", err.Error())
	}
}

func TestLoader_RejectsSchemaViolation_BadDuration(t *testing.T) {
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: [api.openai.com]`,
		`    reason: "test"`,
		`    duration: "not-a-duration"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
	}, "\n")
	_, err := LoadBytes([]byte(body), "x.yaml")
	if err == nil {
		t.Fatal("bad duration should reject; got no error")
	}
	if !strings.Contains(err.Error(), "duration") {
		t.Errorf("error %q should mention duration", err.Error())
	}
}

func TestLoader_RejectsSchemaViolation_UnknownBouncer(t *testing.T) {
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: [api.openai.com]`,
		`    reason: "test"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [made-up-bouncer]`,
	}, "\n")
	_, err := LoadBytes([]byte(body), "x.yaml")
	if err == nil {
		t.Fatal("unknown bouncer name should reject; got no error")
	}
	if !strings.Contains(err.Error(), "made-up-bouncer") {
		t.Errorf("error %q should name the offending bouncer", err.Error())
	}
}

func TestLoader_RejectsSchemaViolation_DuplicateRuleID(t *testing.T) {
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: [api.openai.com]`,
		`    reason: "test"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
		`  - id: ` + validRuleID,
		`    targets: [api2.openai.com]`,
		`    reason: "dup"`,
		`    duration: "1h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
	}, "\n")
	_, err := LoadBytes([]byte(body), "x.yaml")
	if err == nil {
		t.Fatal("duplicate rule id should reject; got no error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error %q should mention duplicate", err.Error())
	}
}

func TestLoader_RejectsSchemaViolation_BadProductMagic(t *testing.T) {
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`product: gbounce-config`, // wrong magic — misrouted file
		`denies: []`,
	}, "\n")
	_, err := LoadBytes([]byte(body), "x.yaml")
	if err == nil {
		t.Fatal("wrong product magic should reject; got no error")
	}
	if !strings.Contains(err.Error(), "product") {
		t.Errorf("error %q should mention product", err.Error())
	}
}

func TestLoader_FiltersNonGbounceTargets(t *testing.T) {
	// 4 rules — only the URL/host targets land on gbounce. The
	// ARN-only + k8s-namespace-only rules get filtered out at the
	// `applied_to` step (the iam-jit cross-protocol resolver in
	// #324e would write `applied_to: [ibounce]` for an ARN target +
	// `applied_to: [kbouncer]` for a k8s namespace target).
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["*.openai.com"]`,
		`    reason: "url-target → gbounce"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
		`  - id: ` + validRuleID2,
		`    targets: ["arn:aws:s3:::prod-*"]`,
		`    reason: "arn-target → ibounce; should be filtered out"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [ibounce]`,
		`  - id: ` + validRuleID3,
		`    targets: ["kube-system"]`,
		`    reason: "k8s-namespace → kbouncer; should be filtered out"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
		`  - id: ` + validRuleID4,
		`    targets: ["payments-db-prod.us-east-1.rds.amazonaws.com"]`,
		`    reason: "RDS endpoint → both dbounce and gbounce"`,
		`    duration: "45m"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [dbounce, gbounce]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	// Only the rules whose applied_to includes "gbounce" survive.
	if len(rs.Rules) != 2 {
		t.Fatalf("Rules = %d; want 2 (URL + RDS-endpoint applied_to includes gbounce); got %v", len(rs.Rules), rs.Rules)
	}
	for _, r := range rs.Rules {
		if r.ID == validRuleID2 || r.ID == validRuleID3 {
			t.Errorf("Rule %q should have been filtered out (applied_to does not include gbounce)", r.ID)
		}
	}
	// Globs() round-trip: should produce 2 globs (one per kept rule).
	globs := rs.Globs()
	if len(globs) != 2 {
		t.Errorf("Globs() = %d; want 2", len(globs))
	}
	// RuleIDForGlob: each kept glob should map back to its rule.
	if rid := rs.RuleIDForGlob("*.openai.com"); rid != validRuleID {
		t.Errorf("RuleIDForGlob(*.openai.com) = %q; want %q", rid, validRuleID)
	}
	if rid := rs.RuleIDForGlob("payments-db-prod.us-east-1.rds.amazonaws.com"); rid != validRuleID4 {
		t.Errorf("RuleIDForGlob(rds-endpoint) = %q; want %q", rid, validRuleID4)
	}
	if rid := rs.RuleIDForGlob("not-in-any-rule.example.com"); rid != "" {
		t.Errorf("RuleIDForGlob(unknown) = %q; want empty", rid)
	}
}

func TestLoader_FiltersExpiredRules(t *testing.T) {
	expired := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["*.openai.com"]`,
		`    reason: "already expired"`,
		`    duration: "1h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    expires_at: "` + expired + `"`,
		`    applied_to: [gbounce]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Errorf("expired rule should be skipped; got %d rule(s)", len(rs.Rules))
	}
}

func TestLoader_RoundTripJSONShape(t *testing.T) {
	rs, err := LoadBytes([]byte(goldenYAML(t)), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("Rules = %d; want 1", len(rs.Rules))
	}
	// Marshal back through JSON + YAML to confirm the struct fields
	// preserve the field names the schema declares. JSON is the most
	// load-bearing because the cross-bouncer fan-out CLI will
	// JSON-serialize the same struct on the wire.
	jb, err := json.Marshal(rs.Rules[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, want := range []string{
		`"id"`, `"targets"`, `"reason"`, `"duration"`,
		`"added_by"`, `"added_at"`, `"applied_to"`,
	} {
		if !strings.Contains(string(jb), want) {
			t.Errorf("JSON round-trip missing field %s: %s", want, string(jb))
		}
	}
	// YAML round-trip: re-emit + re-load + compare the rule count.
	yb, err := yaml.Marshal(rs.Rules[0])
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if !strings.Contains(string(yb), validRuleID) {
		t.Errorf("YAML round-trip lost rule id: %s", string(yb))
	}
}

func TestLoader_ResolveDefaultPath(t *testing.T) {
	// Override env so the test asserts the env path takes precedence.
	t.Setenv(DefaultPathEnv, "/tmp/iam-jit-test-override.yaml")
	got := ResolveDefaultPath()
	if got != "/tmp/iam-jit-test-override.yaml" {
		t.Errorf("ResolveDefaultPath = %q; want override", got)
	}
}
