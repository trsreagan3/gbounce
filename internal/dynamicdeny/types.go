// Package dynamicdeny implements gbounce's consumer side of the
// cross-product dynamic-deny rules surface (#324d).
//
// The full cross-product design lives in the iam-roles repo at
// `docs/DYNAMIC-DENY-RULES.md`; the on-disk YAML shape is described by
// `docs/schemas/dynamic-denies-v1.json`. This package implements:
//
//   - Loader: reads + validates `~/.iam-jit/dynamic-denies.yaml`
//     against the v1.0 schema shape, filters down to rules whose
//     `applied_to` includes `gbounce`.
//   - Watcher: fsnotify-driven hot reload of the YAML file. On parse
//     error, retains the previous in-memory rule set (fail-closed per
//     `[[ibounce-honest-positioning]]`) + emits an admin-action OCSF
//     event so the operator sees the failure without grepping.
//
// The matcher itself lives in `internal/proxy/deny_hosts.go`; this
// package only produces the operator-written form of each glob entry
// (a string the existing `ParseDenyHost` accepts), so the proxy hot
// path stays unchanged shape vs. the pre-#324d static-only world.
package dynamicdeny

import "time"

// Rule is one dynamic-deny rule, deserialized from the YAML file +
// filtered for gbounce applicability. Mirrors the on-disk schema field
// names so a future yaml-round-trip writer can reuse this struct as-is.
type Rule struct {
	// ID is the rule's stable identifier (`dd_<ULID>`). Surfaces in the
	// audit `ext.dynamic_deny_rule_id` field when the rule fires.
	ID string `yaml:"id" json:"id"`
	// Targets are the operator-supplied target patterns. For gbounce
	// these are URLs, hostnames, and host globs; we feed each into the
	// existing `internal/proxy.ParseDenyHost` matcher.
	Targets []string `yaml:"targets" json:"targets"`
	// Reason is the operator's free-text reason — surfaces in the deny
	// audit event verbatim so a downstream operator sees `why` without
	// context-switching.
	Reason string `yaml:"reason" json:"reason"`
	// Duration is the Go-style duration string (`30m`, `3h`, `7d`) or
	// the literal `permanent`. Anchors `ExpiresAt`.
	Duration string `yaml:"duration" json:"duration"`
	// AddedBy / AddedAt / ExpiresAt are audit-trail metadata. ExpiresAt
	// is nil for `duration: permanent`.
	AddedBy   string     `yaml:"added_by" json:"added_by"`
	AddedAt   time.Time  `yaml:"added_at" json:"added_at"`
	ExpiresAt *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
	// AppliedTo names which bouncer(s) this rule applies to. The loader
	// filters for entries containing `"gbounce"` before returning.
	AppliedTo []string `yaml:"applied_to" json:"applied_to"`
	// AppliesToRecommender is consumed by the iam-jit recommender
	// (#324f); gbounce ignores it but preserves the field so a
	// round-trip writer doesn't lose data.
	AppliesToRecommender bool `yaml:"applies_to_recommender" json:"applies_to_recommender"`
	// Source provenance — cli / mcp / org-distributed / imported.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
	// OrgDistributedURL is only present when Source == "org-distributed".
	OrgDistributedURL string `yaml:"org_distributed_url,omitempty" json:"org_distributed_url,omitempty"`
}

// File is the top-level on-disk YAML shape. Field names match the
// v1.0 schema byte-for-byte so a round-trip writer can emit the same
// file an operator hand-edits.
type File struct {
	SchemaVersion      string `yaml:"schema_version" json:"schema_version"`
	Product            string `yaml:"product,omitempty" json:"product,omitempty"`
	ExportedAt         string `yaml:"exported_at,omitempty" json:"exported_at,omitempty"`
	SourceHostnameHash string `yaml:"source_hostname_hash,omitempty" json:"source_hostname_hash,omitempty"`
	Denies             []Rule `yaml:"denies" json:"denies"`
}

// RuleSet is the in-memory snapshot the proxy consults. Two parallel
// slices keep the operator-written glob (passed to the static-rule
// matcher) aligned with the rule that authored it; the matcher then
// uses the index to surface the rule id in the deny audit event.
type RuleSet struct {
	// Rules are the filtered + active rules (applied_to contains
	// "gbounce" AND not expired at load time).
	Rules []Rule
	// SourcePath is the path the rules were loaded from. Surfaces in
	// the startup banner + the /healthz response so an operator who
	// configured a non-default path sees it back.
	SourcePath string
	// LoadedAt is the wall-clock timestamp the snapshot was built.
	// Surfaces in /healthz so an operator can see "last successful
	// reload was N seconds ago."
	LoadedAt time.Time
}

// Empty returns an empty RuleSet — used by callers that need a
// non-nil placeholder before the first load.
func Empty() *RuleSet { return &RuleSet{Rules: nil} }

// Globs returns the operator-written target globs across all active
// gbounce-applicable rules, deduplicated in first-seen order. The
// proxy unions this with the static `--deny-host`/`--deny-hosts-file`
// list before calling `proxy.ParseDenyHosts`.
func (rs *RuleSet) Globs() []string {
	if rs == nil || len(rs.Rules) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		for _, t := range r.Targets {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// RuleIDForGlob returns the id of the first rule whose Targets list
// contains the given operator-written glob. Used by the proxy to
// label a deny audit event with `ext.dynamic_deny_rule_id` when the
// matching glob came from the dynamic side. Returns "" when the glob
// is not in any active rule (i.e. the match came from a static
// `--deny-host` entry).
func (rs *RuleSet) RuleIDForGlob(glob string) string {
	if rs == nil {
		return ""
	}
	for _, r := range rs.Rules {
		for _, t := range r.Targets {
			if t == glob {
				return r.ID
			}
		}
	}
	return ""
}
