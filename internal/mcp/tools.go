// MCP tool descriptors for gbounce.
//
// Each tool entry mirrors the Python iam-jit-bouncer `bouncer_*` +
// kbouncer's `kbounce_*` + dbounce's `dbounce_*` shape:
//
//	name         the gbounce_* tool name agents will see
//	description  agent-readable summary (one paragraph max)
//	inputSchema  JSON-Schema for the arguments
//
// Schema convention follows the sibling products: type/properties/
// required. We do not use $ref or composition.
//
// #363 / §A32 — gbounce MCP surface. The tool list is intentionally
// smaller than dbounce's (which has a SQL parser, prompts, bulk-answer,
// etc) — gbounce v1.0 only ships discovery + MITM modes + dynamic
// denies, so the agent-facing introspection surface focuses on those.

package mcp

// ToolDescriptors returns the full tool list surfaced via
// `tools/list`. Returned as a slice (not a map) so the order is
// deterministic across runs.
func ToolDescriptors() []map[string]any {
	return []map[string]any{
		{
			"name": "gbounce_active_mode",
			"description": "Return gbounce's current operating mode " +
				"(discovery | mitm) plus the active profile name (if any). " +
				"Read-only: agents introspect; they cannot flip the mode " +
				"(that requires a proxy restart per " +
				"[[agent-friendly-not-bypassable]]). Mirrors " +
				"dbounce_active_mode / kbounce_active_mode.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "gbounce_recommend_mode_for_task",
			"description": "DETERMINISTIC (not LLM) recommendation: given " +
				"a task description and/or hint verbs, return 'discovery' " +
				"or 'mitm' per the [[bouncer-mode-selection-for-agents]] " +
				"HTTP-shaped decision matrix. Tasks describing observation/" +
				"audit-only outbound traffic → discovery. Tasks describing " +
				"enforcement of URL-path or method or body predicates → mitm. " +
				"The agent's own LLM should NOT second-guess this — the " +
				"answer is deterministic by design so the decision is " +
				"auditable.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"description": map[string]any{
						"type":        "string",
						"description": "Human-readable task description (free-text).",
					},
					"wants_audit_only": map[string]any{
						"type":        "boolean",
						"description": "True if the task is observation-only (no enforcement needed).",
					},
					"needs_url_path_enforcement": map[string]any{
						"type":        "boolean",
						"description": "True if the task needs to gate by URL path / method / body shape (MITM-only visibility).",
					},
				},
			},
		},
		{
			"name": "gbounce_dynamic_denies_list",
			"description": "Return the list of currently-loaded dynamic-deny " +
				"rules applied to gbounce (from " +
				"`~/.iam-jit/dynamic-denies.yaml` or `--dynamic-denies-path`). " +
				"Read-only. Each entry carries id, targets, reason, " +
				"added_by, added_at, expires_at, source. Useful for an " +
				"agent that wants to introspect 'what hosts is gbounce " +
				"currently blocking dynamically?' before recommending an " +
				"action.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "gbounce_deny_add",
			"description": "Append a dynamic-deny rule to the " +
				"dynamic-denies YAML file (default " +
				"`~/.iam-jit/dynamic-denies.yaml`). Mutating tool — the " +
				"running proxy picks up the new rule on the next fsnotify " +
				"event. The new rule is scoped to gbounce only " +
				"(applied_to=[gbounce]); cross-product fan-out requires the " +
				"operator hand-edits applied_to. Returns the minted rule id " +
				"(`dd_<ULID>`).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{
						"type":        "string",
						"description": "Hostname or `*.domain` glob to deny.",
					},
					"reason": map[string]any{
						"type":        "string",
						"description": "Operator's free-text reason (lands in the deny audit event).",
					},
					"duration": map[string]any{
						"type":        "string",
						"description": "Duration string (`30m`, `3h`, `7d`) or the literal `permanent`. Default `permanent`.",
					},
					"added_by": map[string]any{
						"type":        "string",
						"description": "Operator handle stamped into the rule's added_by field. Default `gbounce-mcp`.",
					},
				},
				"required": []string{"target", "reason"},
			},
		},
		{
			"name": "gbounce_deny_remove",
			"description": "Remove a dynamic-deny rule by id (from " +
				"gbounce_dynamic_denies_list). Mutating tool — the running " +
				"proxy picks up the removal on the next fsnotify event.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "The rule id (`dd_<ULID>`) returned by gbounce_dynamic_denies_list / gbounce_deny_add.",
					},
				},
				"required": []string{"id"},
			},
		},
	}
}
