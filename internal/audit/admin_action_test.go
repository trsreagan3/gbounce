package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeAdminActionEvent_ConfigExportShape(t *testing.T) {
	ev := MakeAdminActionEvent(AdminActionInput{
		Action:     AdminActionConfigExport,
		Actor:      "alice",
		EntityKind: "config",
		EntityName: "/tmp/bundle.json",
		Source:     AdminActionSourceCLI,
		After:      map[string]any{"product": "gbounce", "rows": 0},
	})
	if ev.ClassUID != ClassUID {
		t.Errorf("class_uid = %d; want %d", ev.ClassUID, ClassUID)
	}
	if ev.ActivityName != string(AdminActionConfigExport) {
		t.Errorf("activity_name = %q", ev.ActivityName)
	}
	if ev.ActivityID != ActivityOther {
		t.Errorf("activity_id = %d; want Other(%d)", ev.ActivityID, ActivityOther)
	}
	if ev.Metadata.Product.Name != ProductName {
		t.Errorf("product = %q", ev.Metadata.Product.Name)
	}
	cc, ok := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
	if !ok {
		t.Fatalf("config_change block missing: %+v", ev.Unmapped.IAMJIT.Ext)
	}
	if cc["type"] != string(AdminActionConfigExport) {
		t.Errorf("config_change.type = %v", cc["type"])
	}
	if cc["entity"] != "/tmp/bundle.json" {
		t.Errorf("config_change.entity = %v", cc["entity"])
	}
	if _, hasAfter := cc["after_hash"]; !hasAfter {
		t.Error("after_hash should be present when After is non-nil")
	}
	if _, hasBefore := cc["before_hash"]; hasBefore {
		t.Error("before_hash should be absent when Before is nil")
	}
}

func TestMakeAdminActionEvent_ConfigImportIsCreate(t *testing.T) {
	ev := MakeAdminActionEvent(AdminActionInput{
		Action: AdminActionConfigImport,
	})
	if ev.ActivityID != ActivityCreate {
		t.Errorf("activity_id = %d; want Create(%d)", ev.ActivityID, ActivityCreate)
	}
}

func TestMakeAdminActionEvent_DefaultsSourceToCLI(t *testing.T) {
	ev := MakeAdminActionEvent(AdminActionInput{
		Action: AdminActionConfigExport,
	})
	cc, _ := ev.Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
	if cc["source"] != string(AdminActionSourceCLI) {
		t.Errorf("source default = %v; want %q", cc["source"], AdminActionSourceCLI)
	}
}

func TestHashState_DeterministicAcrossCalls(t *testing.T) {
	v := map[string]any{"a": 1, "b": 2, "c": []int{1, 2, 3}}
	h1, ok1 := HashState(v)
	h2, ok2 := HashState(v)
	if !ok1 || !ok2 {
		t.Fatal("HashState should succeed on map input")
	}
	if h1 != h2 {
		t.Errorf("hashes differ: %q vs %q", h1, h2)
	}
	// Hex sha256 is 64 chars.
	if len(h1) != 64 {
		t.Errorf("hash length = %d; want 64", len(h1))
	}
}

func TestHashState_NilReturnsNotOK(t *testing.T) {
	h, ok := HashState(nil)
	if ok {
		t.Errorf("HashState(nil) should return ok=false; got h=%q", h)
	}
}

func TestEmitAdminAction_NilLogWriterIsNoop(t *testing.T) {
	// Must not panic.
	EmitAdminAction(context.Background(), nil, AdminActionInput{
		Action: AdminActionConfigExport,
	})
}

func TestEmitAdminAction_WritesToJSONL(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	lw, err := NewLogWriter(context.Background(), LogWriterOptions{
		Path:  logPath,
		Fsync: true,
	})
	if err != nil {
		t.Fatalf("NewLogWriter: %v", err)
	}
	EmitAdminAction(context.Background(), lw, AdminActionInput{
		Action:     AdminActionConfigImport,
		Actor:      "bob",
		EntityKind: "config",
		EntityName: "/tmp/bundle.json",
		After:      map[string]any{"mode": "merge"},
	})
	lw.Close()

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var found bool
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "config.import") {
			continue
		}
		var ev map[string]any
		if jerr := json.Unmarshal([]byte(line), &ev); jerr != nil {
			t.Fatalf("decode event: %v", jerr)
		}
		if ev["activity_name"] != "config.import" {
			t.Errorf("activity_name = %v", ev["activity_name"])
		}
		found = true
	}
	if !found {
		t.Error("config.import event missing from audit log")
	}
}

func TestAdminActionActivityID_AllKnownActions(t *testing.T) {
	cases := map[AdminAction]int{
		AdminActionConfigExport: ActivityOther,
		AdminActionConfigImport: ActivityCreate,
	}
	for action, want := range cases {
		if got := AdminActionActivityID(action); got != want {
			t.Errorf("AdminActionActivityID(%q) = %d; want %d", action, got, want)
		}
	}
}
