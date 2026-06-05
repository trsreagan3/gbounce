package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRunConfig_ParsesAllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
mode: mitm
allow_connect: true
audit_log_path: /var/log/gbounce.jsonl
ui_exclude_hosts:
  - "*.datadoghq.com"
  - metrics.internal
deny_hosts:
  - evil.example.com
audit_object_storage:
  endpoint: https://s3.us-east-1.amazonaws.com
  bucket: bounce-audit
  prefix: prod
  region: us-east-1
  rotation_minutes: 10
  max_size_mb: 32
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, found, err := LoadRunConfig(path)
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if rc.Mode != "mitm" {
		t.Errorf("mode=%q", rc.Mode)
	}
	if rc.AllowConnect == nil || !*rc.AllowConnect {
		t.Errorf("allow_connect not parsed as true")
	}
	if rc.AuditLogPath != "/var/log/gbounce.jsonl" {
		t.Errorf("audit_log_path=%q", rc.AuditLogPath)
	}
	if len(rc.UIExcludeHosts) != 2 || rc.UIExcludeHosts[0] != "*.datadoghq.com" {
		t.Errorf("ui_exclude_hosts=%v", rc.UIExcludeHosts)
	}
	if rc.AuditObjectStorage == nil || rc.AuditObjectStorage.Bucket != "bounce-audit" ||
		rc.AuditObjectStorage.RotationMinutes != 10 {
		t.Errorf("audit_object_storage=%+v", rc.AuditObjectStorage)
	}
}

func TestLoadRunConfig_ParsesAnomalyBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
mode: discovery
anomaly_detection:
  enabled: true
  mode: block
  sensitivity: high
  min_actions_for_baseline: 25
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, found, err := LoadRunConfig(path)
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if rc.Anomaly == nil {
		t.Fatal("anomaly_detection block not parsed")
	}
	if !rc.Anomaly.Enabled || rc.Anomaly.Mode != "block" ||
		rc.Anomaly.Sensitivity != "high" || rc.Anomaly.MinActions != 25 {
		t.Errorf("anomaly block=%+v", rc.Anomaly)
	}
}

func TestLoadRunConfig_MissingFileIsNoOp(t *testing.T) {
	rc, found, err := LoadRunConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil || found || rc != nil {
		t.Fatalf("missing file should be (nil,false,nil); got rc=%v found=%v err=%v", rc, found, err)
	}
	// Empty path is also a no-op.
	if _, found, err := LoadRunConfig(""); found || err != nil {
		t.Fatalf("empty path should be no-op")
	}
}

func TestLoadRunConfig_UnknownKeyIsLoudError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("typo_field: oops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadRunConfig(path); err == nil {
		t.Fatal("a typo'd/unknown key must be a loud error, not silently ignored")
	}
}

func TestResolvePrecedence(t *testing.T) {
	// String: file value applies only when the flag was NOT changed.
	if got := resolveString(false, "fromFile", "flagDefault"); got != "fromFile" {
		t.Errorf("unchanged flag should take file value; got %q", got)
	}
	if got := resolveString(true, "fromFile", "explicitFlag"); got != "explicitFlag" {
		t.Errorf("explicit flag must override file; got %q", got)
	}
	if got := resolveString(false, "", "flagDefault"); got != "flagDefault" {
		t.Errorf("empty file value must not clobber the flag default; got %q", got)
	}

	// Slice.
	if got := resolveStringSlice(false, []string{"a"}, nil); len(got) != 1 {
		t.Errorf("unchanged flag should take file slice")
	}
	if got := resolveStringSlice(true, []string{"a"}, []string{"b"}); got[0] != "b" {
		t.Errorf("explicit flag slice must override file")
	}

	// Bool pointer (nil = unset in file).
	tru := true
	if got := resolveBool(false, &tru, false); !got {
		t.Errorf("unchanged flag should take file bool")
	}
	if got := resolveBool(true, &tru, false); got {
		t.Errorf("explicit flag bool must override file")
	}
	if got := resolveBool(false, nil, true); !got {
		t.Errorf("nil file bool must not clobber flag value")
	}

	// Int (0 = unset in file).
	if got := resolveInt(false, 10, 5); got != 10 {
		t.Errorf("unchanged flag should take file int")
	}
	if got := resolveInt(false, 0, 5); got != 5 {
		t.Errorf("zero file int must not clobber flag value")
	}
	if got := resolveInt(true, 10, 5); got != 5 {
		t.Errorf("explicit flag int must override file")
	}
}
