// Posture MCP-tool tests per #383 / §A42.

package mcp

import (
	"testing"
)

// TestMCP_PostureReturnsBlock confirms the gbounce_posture tool dispatches
// successfully + returns a result with the documented top-level keys.
func TestMCP_PostureReturnsBlock(t *testing.T) {
	t.Setenv("GBOUNCE_MODE", "mitm")
	t.Setenv("GBOUNCE_PROFILE", "discovery-only")
	srv := &Server{}
	resp, err := srv.toolPosture(nil)
	if err != nil {
		t.Fatalf("toolPosture: %v", err)
	}
	for _, k := range []string{
		"schema_version", "bouncer", "captured_at", "running",
		"port", "default_port", "mode", "active_profile",
	} {
		if _, ok := resp[k]; !ok {
			t.Errorf("missing key %q in posture MCP response", k)
		}
	}
	if resp["bouncer"] != "gbounce" {
		t.Errorf("bouncer=%v want gbounce", resp["bouncer"])
	}
	if resp["mode"] != "mitm" {
		t.Errorf("mode=%v want mitm", resp["mode"])
	}
}

// TestMCP_PostureToolDescriptorPresent confirms gbounce_posture is
// included in the tool descriptor list so MCP clients see it via
// tools/list.
func TestMCP_PostureToolDescriptorPresent(t *testing.T) {
	tools := ToolDescriptors()
	for _, td := range tools {
		if td["name"] == "gbounce_posture" {
			return
		}
	}
	t.Errorf("gbounce_posture missing from ToolDescriptors() output")
}
