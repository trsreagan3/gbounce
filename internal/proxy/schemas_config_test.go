package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSchemasConfigEndpointServesEmbeddedSchema confirms
// `GET /schemas/config` returns the same bytes that ship in
// schemas/gbounce-config.schema.json.
func TestSchemasConfigEndpointServesEmbeddedSchema(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/schemas/config", nil)
	rec := httptest.NewRecorder()
	schemasConfigHandler(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/schema+json") {
		t.Errorf("content-type: got %q, want application/schema+json prefix", got)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	wantPath := repoSchemaPath(t)
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read in-tree schema %s: %v", wantPath, err)
	}
	if !bytes.Equal(want, body) {
		t.Fatalf(
			"served schema diverged from %s — re-copy the published "+
				"schema into internal/proxy/schemas_config.json",
			wantPath,
		)
	}
}

// TestSchemasConfigEndpointReturnsValidJSONSchema: parses + post-#288
// wire-shape (string semver schema_version).
func TestSchemasConfigEndpointReturnsValidJSONSchema(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/schemas/config", nil)
	rec := httptest.NewRecorder()
	schemasConfigHandler(rec, req)

	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(body, &schema); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties: missing or wrong type")
	}
	sv, ok := props["schema_version"].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties.schema_version: missing or wrong type")
	}
	if sv["type"] != "string" {
		t.Errorf("schema_version.type: got %v, want string", sv["type"])
	}
	enumVals, ok := sv["enum"].([]any)
	if !ok || len(enumVals) != 1 || enumVals[0] != "1.0" {
		t.Errorf("schema_version.enum: got %v, want [\"1.0\"]", sv["enum"])
	}
	prod, ok := props["product"].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties.product: missing or wrong type")
	}
	prodEnum, ok := prod["enum"].([]any)
	if !ok || len(prodEnum) != 1 || prodEnum[0] != "gbounce" {
		t.Errorf("product.enum: got %v, want [\"gbounce\"]", prod["enum"])
	}
}

// TestSchemasConfigEndpointRejectsNonGet: PUT / POST / DELETE return
// 405 — the schema is READ-only metadata.
func TestSchemasConfigEndpointRejectsNonGet(t *testing.T) {
	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
	} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/schemas/config", nil)
			rec := httptest.NewRecorder()
			schemasConfigHandler(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("status: got %d, want 405", resp.StatusCode)
			}
			if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
				t.Errorf("Allow header: got %q, want %q", got, "GET, HEAD")
			}
		})
	}
}

// repoSchemaPath returns the absolute path to the published
// gbounce-config schema file.
func repoSchemaPath(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(here)))
	return filepath.Join(root, "schemas", "gbounce-config.schema.json")
}
