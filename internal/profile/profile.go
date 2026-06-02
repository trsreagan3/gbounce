// Package profile — profile.go
//
// gbounce profile YAML on-disk schema + loader.
//
// §A27 (#352) introduces a YAML profile install surface so the
// `iam-jit profile generate-from-audit` generator's per-bouncer
// `gbounce.yaml` slot can be installed by gbounce directly. Pre-§A27
// gbounce only consumed profile rules via `--profile-rules-file`
// (JSON), so the generator's output passed through unenforced —
// breaking the launch claim that "the generator emits a working
// profile for all 4 bouncers." This file (plus install.go) closes
// that gap.
//
// On-disk shape:
//
//	profiles:
//	  staging-no-imds:
//	    description: "block IMDS + DoH"
//	    source: ""                      # local | URL string
//	    deny_hosts:
//	      - 169.254.169.254
//	      - "*.openai.com"
//	    deny_rules:
//	      - host: api.openai.com
//	        method: [POST]
//	        path_prefix: /v1/chat/
//	        reason: "no chat-completions in staging"
//
// Generator shape (consumed via UnmarshalYAML's shim so the generator
// emits a single per-bouncer file that installs without a manual
// translation step):
//
//	schema_version: 1
//	profile_name: my-bundle-gbounce
//	bouncer: gbounce
//	provenance: {...}
//	denies:
//	  - target: 169.254.169.254
//	    reason: IMDS access from agent context is credential exfiltration
//	  - target: "*.openai.com"
//	    actions: [POST]
//	    reason: "no chat-completions in staging"
//	allows:
//	  - target: api.example.com
//	    actions: [GET]
//
// The shim's `denies[].target` → DenyHosts when no `actions:` are
// specified AND the target is hostname-shaped (no `/`); otherwise it
// becomes a DenyRule with the target as host + actions as methods.
// `allows:` entries land in AllowRules and ARE enforced (iam-jit
// #377): in MITM mode an allow_rule that matches an outbound request
// overrides a would-be profile deny_rule deny, mirroring dbounce's
// matchAnyAllowRule precedence. They sit ABOVE the finer-grained
// deny_rules but BELOW the deny_hosts hard floor (deny_hosts is
// evaluated at the CONNECT pre-dial gate, before MITM allow-rule
// evaluation, so an allow_rule cannot resurrect a deny_hosts-blocked
// destination — the exact dbounce "deny WINS" posture).
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile is one named YAML profile. Mirrors the dbounce / kbouncer /
// ibounce Profile shape at the fields gbounce actually enforces; the
// shape is intentionally NOT identical to the SQL-side dbounce
// Profile (gbounce has no statement-shape semantics).
type Profile struct {
	// Name is the YAML key, set by LoadProfiles after parsing.
	Name string `yaml:"-"`

	// Description is the human-readable summary shown by `profile list`
	// and surfaced in audit reasons. Optional.
	Description string `yaml:"description,omitempty"`

	// DenyHosts is the list of operator-written host entries the
	// proxy's CONNECT + reverse-proxy + MITM handlers consult before
	// dialing. Each entry parses through ParseDenyHost (same semantics
	// as `--deny-host`): exact-match or single-leading-`*.` wildcard.
	DenyHosts []string `yaml:"deny_hosts,omitempty"`

	// DenyRules is the list of richer profile rules (host + port +
	// method + path predicates). Each entry compiles through
	// ParseRule on profile load; the compiled []Rule lives on the
	// runtime side (CLI loader) so this struct stays pure-data.
	//
	// Predicates that require MITM (method / path / query_params) are
	// SKIPPED at match time in CONNECT-only mode — see
	// FirstMatch's `mitmActive` arg.
	DenyRules []RuleSpec `yaml:"deny_rules,omitempty"`

	// AllowRules is the profile-scoped allow-list. Each entry compiles
	// through ParseRule (same predicate shape as DenyRules). In MITM
	// mode the proxy consults the compiled allow-rule list BEFORE the
	// deny_rules layer: an allow_rule match overrides a would-be
	// deny_rule deny (source=profile.allow). It does NOT override a
	// deny_hosts entry — deny_hosts is the hard floor, evaluated at the
	// CONNECT pre-dial gate before any MITM allow-rule evaluation.
	// Mirrors dbounce's Profile.Evaluate Order 4 (matchAnyAllowRule
	// runs AFTER the deny hard floors). Predicates that require MITM
	// (method / path / query_params) are SKIPPED in CONNECT-only mode,
	// same as DenyRules.
	AllowRules []RuleSpec `yaml:"allow_rules,omitempty"`

	// Source records provenance. Empty or "local" → user-edited.
	// A URL / absolute-file-path (set by `profile install`) →
	// org-distributed, READ-ONLY at the CLI surface (UpsertProfile
	// refuses to overwrite a non-local source). Mirrors the
	// kbouncer / dbounce / ibouncer field of the same name.
	Source string `yaml:"source,omitempty"`

	// InjectionScanResponseBodies (iam-jit #730) — opt-in indirect-
	// prompt-injection response-body scanner. Default OFF; only
	// honored when the proxy is in MITM mode (response bodies aren't
	// visible in CONNECT mode). Per [[mitm-beta-pii-pci-concern]]
	// MITM ships BETA; this feature inherits that posture.
	InjectionScanResponseBodies InjectionScanConfig `yaml:"injection_scan_response_bodies,omitempty"`

	// ValidateToolCalls (iam-jit #729 / BUILD-8) — opt-in hallucinated-
	// tool-call validator. Inspects OUTBOUND MCP / OpenAI / Anthropic
	// tool-call request bodies + rejects calls whose name + arguments
	// don't match the known-tool schema corpus. Default OFF. Only
	// honored in MITM mode (request bodies inspectable without TLS
	// termination only when the upstream is plain HTTP).
	ValidateToolCalls ValidateToolCallsConfig `yaml:"validate_tool_calls,omitempty"`
}

// ValidateToolCallsConfig is the per-profile hallucinated-tool-call-
// validator config. Mirrors iam-roles/src/iam_jit/tool_call_validator/
// config.py field-for-field.
type ValidateToolCallsConfig struct {
	// Enabled is the on/off toggle. Default false.
	Enabled bool `yaml:"enabled,omitempty"`

	// Action is one of: warn | strip | deny. Default warn.
	Action string `yaml:"action,omitempty"`

	// SchemaCorpusPath is an optional path/URL to an operator-supplied
	// schema-corpus override file. Empty = baked-in corpus only.
	SchemaCorpusPath string `yaml:"schema_corpus_path,omitempty"`

	// AllowlistPatterns are regexes; matches suppress detection.
	AllowlistPatterns []string `yaml:"allowlist_patterns,omitempty"`

	// MaxBodyBytes caps the scanned body size (ReDoS guard).
	// Default 64 KiB.
	MaxBodyBytes int `yaml:"max_body_bytes,omitempty"`

	// MinConfidenceForDeny: when Action==deny, results below this
	// confidence downgrade to warn. Default 0.7.
	MinConfidenceForDeny float64 `yaml:"min_confidence_for_deny,omitempty"`
}

// InjectionScanConfig is the per-profile response-body scanner config.
// Mirrors iam-roles/src/iam_jit/injection_scanner/config.py field-for-field.
type InjectionScanConfig struct {
	// Enabled is the on/off toggle. Default false.
	Enabled bool `yaml:"enabled,omitempty"`

	// Action is one of: warn | strip | deny. Default warn.
	Action string `yaml:"action,omitempty"`

	// AllowlistPatterns are regexes; matches suppress detection.
	AllowlistPatterns []string `yaml:"allowlist_patterns,omitempty"`

	// MaxBodyBytes caps the scanned body size (ReDoS guard).
	// Default 64 KiB. Bodies above this are truncated before scanning.
	MaxBodyBytes int `yaml:"max_body_bytes,omitempty"`

	// MinConfidenceForDeny: when Action==deny, results below this
	// confidence downgrade to warn. Default 0.7.
	MinConfidenceForDeny float64 `yaml:"min_confidence_for_deny,omitempty"`
}

// IsLocalSource reports whether the profile is editable at the CLI
// surface (i.e., it was not installed from an org URL).
func (p *Profile) IsLocalSource() bool {
	if p == nil {
		return true
	}
	return p.Source == "" || p.Source == "local"
}

// generatorProfileShim is the shape `iam-jit profile generate-from-
// audit` emits per-bouncer (see iam-roles/src/iam_jit/llm/
// profile_generator.py:_render_profile_yaml). UnmarshalYAML on
// Profile decodes BOTH the canonical shape AND this shape so the
// generated YAML can install without a manual translation step.
//
// Per §A27 (#352). Pre-fix, a generator-emitted gbounce.yaml parsed
// into a Profile with every enforcement field empty — denies fired
// for nothing.
type generatorProfileShim struct {
	// SchemaVersion + ProfileName + Bouncer + Provenance are bundle-
	// routing fields; recognized + ignored at parse time (the install
	// path already has the bouncer routing baked in: a gbounce-emitted
	// file installs into gbounce).
	SchemaVersion any `yaml:"schema_version,omitempty"`
	ProfileName   any `yaml:"profile_name,omitempty"`
	Bouncer       any `yaml:"bouncer,omitempty"`
	Provenance    any `yaml:"provenance,omitempty"`

	// Allows + Denies carry the generator's rule lists. For gbounce
	// each entry's `target` is a hostname (possibly wildcard) + the
	// `actions` are HTTP methods. Mapping into the canonical Profile
	// fields is done by the merge step at the bottom of UnmarshalYAML.
	Allows []generatorRule `yaml:"allows,omitempty"`
	Denies []generatorRule `yaml:"denies,omitempty"`

	// FlaggedForReview + Skipped are operator-review metadata,
	// recognized but unused at parse time.
	FlaggedForReview []any `yaml:"flagged_for_review,omitempty"`
	Skipped          []any `yaml:"skipped,omitempty"`
}

// generatorRule is one entry under generator-shape `denies:` /
// `allows:`. The fields are a superset across the four bouncers so
// the same struct decodes ibounce / kbounce / dbounce / gbounce
// rules; the gbounce translator only consults Target + Actions +
// Reason + Bouncer.
type generatorRule struct {
	Target      any      `yaml:"target,omitempty"`
	Actions     []string `yaml:"actions,omitempty"`
	Verbs       []string `yaml:"verbs,omitempty"`
	Resources   []string `yaml:"resources,omitempty"`
	Scope       any      `yaml:"scope,omitempty"`
	SQLPatterns []string `yaml:"sql_patterns,omitempty"`
	Reason      string   `yaml:"reason,omitempty"`
	Bouncer     string   `yaml:"bouncer,omitempty"`
}

// UnmarshalYAML accepts the canonical Profile shape AND the generator
// shape. The two never collide structurally — the canonical shape has
// no `denies:` field at all and the generator shape has no
// `deny_hosts:` field at all — so a body containing fields from
// both shapes is interpreted as the canonical author having layered
// a generator-shape addendum on top (each shape's fields are merged).
//
// Per [[creates-never-mutates]]: pre-existing canonical profiles
// continue to parse identically (the generator-shape fields are
// optional + default to their zero values).
func (p *Profile) UnmarshalYAML(node *yaml.Node) error {
	// First, decode into a type-alias of Profile so the standard
	// yaml.v3 reflection-based decoder runs without recursing into
	// our custom UnmarshalYAML. The Go pattern: alias the type so it
	// loses the method set, decode, copy back.
	type rawProfile Profile
	var canonical rawProfile
	if err := node.Decode(&canonical); err != nil {
		return err
	}
	*p = Profile(canonical)

	// Then decode the same node into the generator shim. yaml.v3
	// silently ignores fields the target struct doesn't declare, so
	// this is a no-op for profiles that don't use the shim's fields.
	var shim generatorProfileShim
	if err := node.Decode(&shim); err != nil {
		return err
	}
	if len(shim.Denies) == 0 && len(shim.Allows) == 0 {
		return nil
	}

	// Merge the shim's rules into the canonical Profile fields.
	mergeGeneratorRules(p, shim.Denies, shim.Allows)
	return nil
}

// mergeGeneratorRules translates the generator's `denies:` / `allows:`
// entries into the canonical DenyHosts + DenyRules + AllowRules slots.
//
// Mapping:
//
//   - A `deny` whose target is a bare hostname (no `/`, no method
//     prefix) AND has no `actions:` becomes a DenyHosts entry. This
//     is the common case for the safety-floor (IMDS, DoH).
//
//   - A `deny` whose target is a hostname AND has `actions:` becomes
//     a DenyRule with host=target + methods=actions. This is the
//     "block POST to api.openai.com" shape.
//
//   - A `deny` whose target contains a `/` is parsed as
//     `<host>/<path>` and becomes a DenyRule with the path under
//     PathPrefix. (Operators wanting exact-path or regex shapes hand-
//     author the canonical deny_rules entry rather than relying on
//     the generator.)
//
//   - A `deny` whose target starts with `*.` is preserved verbatim
//     in DenyHosts (the deny_hosts wildcard semantics handle it) or
//     in DenyRule.Host when actions are present.
//
//   - Per-rule `bouncer:` overrides naming a different product are
//     SKIPPED silently — the install-time bundle routing already
//     targeted this file at gbounce.
//
// Allows are translated symmetrically into AllowRules (which round-
// trip but don't enforce in v1.0). De-dup is by canonical string
// form so layering the generator shape on top of a canonical author's
// deny_hosts entries doesn't create duplicates.
func mergeGeneratorRules(p *Profile, denies, allows []generatorRule) {
	seenHosts := make(map[string]struct{}, len(p.DenyHosts))
	for _, h := range p.DenyHosts {
		seenHosts[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	seenRules := make(map[string]struct{}, len(p.DenyRules))
	for _, r := range p.DenyRules {
		seenRules[canonicalRuleKey(r)] = struct{}{}
	}
	for _, rule := range denies {
		if rule.Bouncer != "" && !strings.EqualFold(rule.Bouncer, "gbounce") {
			continue
		}
		target := stringifyTarget(rule.Target)
		if target == "" {
			continue
		}
		host, path := splitTargetHostPath(target)
		if host == "" {
			continue
		}
		// Bare-hostname + no actions + no path → deny_hosts entry.
		if len(rule.Actions) == 0 && path == "" {
			key := strings.ToLower(host)
			if _, ok := seenHosts[key]; ok {
				continue
			}
			seenHosts[key] = struct{}{}
			p.DenyHosts = append(p.DenyHosts, host)
			continue
		}
		// Otherwise → deny_rules entry with host + (method / path).
		spec := RuleSpec{
			Host:   host,
			Reason: rule.Reason,
		}
		if path != "" {
			spec.PathPrefix = path
		}
		if len(rule.Actions) > 0 {
			methods := make([]string, 0, len(rule.Actions))
			for _, m := range rule.Actions {
				m = strings.TrimSpace(m)
				if m != "" {
					methods = append(methods, strings.ToUpper(m))
				}
			}
			if len(methods) > 0 {
				spec.Method = methods
			}
		}
		key := canonicalRuleKey(spec)
		if _, ok := seenRules[key]; ok {
			continue
		}
		seenRules[key] = struct{}{}
		p.DenyRules = append(p.DenyRules, spec)
	}

	seenAllow := make(map[string]struct{}, len(p.AllowRules))
	for _, r := range p.AllowRules {
		seenAllow[canonicalRuleKey(r)] = struct{}{}
	}
	for _, rule := range allows {
		if rule.Bouncer != "" && !strings.EqualFold(rule.Bouncer, "gbounce") {
			continue
		}
		target := stringifyTarget(rule.Target)
		if target == "" {
			continue
		}
		host, path := splitTargetHostPath(target)
		if host == "" {
			continue
		}
		spec := RuleSpec{
			Host:   host,
			Reason: rule.Reason,
		}
		if path != "" {
			spec.PathPrefix = path
		}
		if len(rule.Actions) > 0 {
			methods := make([]string, 0, len(rule.Actions))
			for _, m := range rule.Actions {
				m = strings.TrimSpace(m)
				if m != "" {
					methods = append(methods, strings.ToUpper(m))
				}
			}
			if len(methods) > 0 {
				spec.Method = methods
			}
		}
		key := canonicalRuleKey(spec)
		if _, ok := seenAllow[key]; ok {
			continue
		}
		seenAllow[key] = struct{}{}
		p.AllowRules = append(p.AllowRules, spec)
	}
}

// stringifyTarget converts a generator-rule Target field (declared
// `any` to tolerate the generator's freer YAML) into a trimmed string.
// Empty / non-string targets return "".
func stringifyTarget(t any) string {
	switch v := t.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	}
	return ""
}

// splitTargetHostPath splits a generator-rule target into (host,
// path). Returns ("", "") for an empty target. A target without a `/`
// is host-only.
//
//   - `169.254.169.254`             → ("169.254.169.254", "")
//   - `*.openai.com`                → ("*.openai.com", "")
//   - `api.openai.com/v1/chat`      → ("api.openai.com", "/v1/chat")
//   - `https://api.openai.com/x`    → scheme is stripped; same as above
func splitTargetHostPath(target string) (string, string) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", ""
	}
	// Strip scheme if present so an operator who copy-pastes a URL
	// from the audit log doesn't end up with `https://host/path`
	// landing in a DenyHosts entry (which would never match).
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.Index(t, "/"); i >= 0 {
		return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i:])
	}
	return t, ""
}

// canonicalRuleKey returns a stable string form of a RuleSpec used to
// de-dup the merge step. We deliberately don't reuse ParseRule's
// describeRule (which expects a compiled Rule); the key here is for
// merge-time identity, not for audit emission.
func canonicalRuleKey(r RuleSpec) string {
	var b strings.Builder
	b.WriteString("host=")
	b.WriteString(strings.ToLower(strings.TrimSpace(r.Host)))
	b.WriteString("|port=")
	fmt.Fprintf(&b, "%d", r.Port)
	if r.Method != nil {
		b.WriteString("|method=")
		switch m := r.Method.(type) {
		case string:
			b.WriteString(strings.ToUpper(m))
		case []string:
			methods := append([]string(nil), m...)
			for i := range methods {
				methods[i] = strings.ToUpper(strings.TrimSpace(methods[i]))
			}
			b.WriteString(strings.Join(methods, ","))
		default:
			fmt.Fprintf(&b, "%v", m)
		}
	}
	if r.Path != "" {
		b.WriteString("|path=")
		b.WriteString(r.Path)
	}
	if r.PathPrefix != "" {
		b.WriteString("|path_prefix=")
		b.WriteString(r.PathPrefix)
	}
	if r.PathRegex != "" {
		b.WriteString("|path_regex=")
		b.WriteString(r.PathRegex)
	}
	if len(r.QueryParams) > 0 {
		b.WriteString("|qp=")
		// Stable ordering by sorting keys.
		keys := make([]string, 0, len(r.QueryParams))
		for k := range r.QueryParams {
			keys = append(keys, k)
		}
		for i := 1; i < len(keys); i++ {
			for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
				keys[j-1], keys[j] = keys[j], keys[j-1]
			}
		}
		for _, k := range keys {
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(r.QueryParams[k])
			b.WriteString("&")
		}
	}
	return b.String()
}

// Profiles is a loaded collection of named profiles plus metadata.
type Profiles struct {
	// Path is the on-disk YAML the profiles were loaded from, or "" when
	// loaded from defaults / in-memory.
	Path string

	// All is the name → Profile map.
	All map[string]*Profile
}

// ErrUnknownProfile is returned by Profiles.Active when the requested
// name is not in the loaded set.
var ErrUnknownProfile = errors.New("gbounce: unknown profile")

// ErrInvalidProfile is returned by LoadProfiles when a profile's
// fields are internally inconsistent.
var ErrInvalidProfile = errors.New("gbounce: invalid profile")

// ErrProfileExists is returned by AddLocalProfile when a profile with
// the requested name already lives on disk.
var ErrProfileExists = errors.New("gbounce: profile already exists")

// profileFile is the on-disk YAML shape.
type profileFile struct {
	Profiles map[string]*Profile `yaml:"profiles"`
}

// LoadProfiles reads profiles.yaml from path and returns the parsed
// collection. If path is "" or the file doesn't exist, an empty
// collection is returned (with Profiles.Path = "") — gbounce ships no
// embedded default profiles (per [[gbounce-profile-doctor-v1-no-
// shipped-defaults]]).
func LoadProfiles(path string) (*Profiles, error) {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err == nil {
			return parseProfiles(raw, path)
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("gbounce: read profiles %q: %w", path, err)
		}
	}
	return &Profiles{Path: "", All: map[string]*Profile{}}, nil
}

// parseProfiles is the shared YAML→Profiles deserializer used by both
// LoadProfiles and the install code paths.
func parseProfiles(raw []byte, path string) (*Profiles, error) {
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("gbounce: parse profiles yaml: %w", err)
	}
	if pf.Profiles == nil {
		pf.Profiles = map[string]*Profile{}
	}
	for name, p := range pf.Profiles {
		if p == nil {
			p = &Profile{}
			pf.Profiles[name] = p
		}
		p.Name = name
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidProfile, name, err)
		}
	}
	return &Profiles{Path: path, All: pf.Profiles}, nil
}

// validate runs a structural check on a profile's compiled fields so
// `profile install` rejects malformed input BEFORE writing.
func (p *Profile) validate() error {
	for i, h := range p.DenyHosts {
		if _, err := ParseDenyHostEntry(h); err != nil {
			return fmt.Errorf("deny_hosts[%d]: %v", i, err)
		}
	}
	for i, spec := range p.DenyRules {
		if _, err := ParseRule(spec); err != nil {
			return fmt.Errorf("deny_rules[%d]: %v", i, err)
		}
	}
	for i, spec := range p.AllowRules {
		if _, err := ParseAllowRule(spec); err != nil {
			return fmt.Errorf("allow_rules[%d]: %v", i, err)
		}
	}
	return nil
}

// ParseDenyHostEntry validates a single deny-host string the same way
// proxy.ParseDenyHost would, but without taking a dependency on the
// proxy package from here. Returns the trimmed entry on success.
//
// We inline a minimal check here rather than importing
// internal/proxy because that would create an import cycle
// (proxy depends on profile via the MITM rules). The contract:
// non-empty, no whitespace, no scheme, no path, no embedded port,
// and either no `*` or a single leading `*.<domain>`.
func ParseDenyHostEntry(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("deny_hosts: empty entry")
	}
	if trimmed == "*" {
		return "", fmt.Errorf(
			"deny_hosts: bare wildcard %q is not allowed", trimmed)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", fmt.Errorf("deny_hosts %q: contains whitespace", raw)
	}
	if strings.Contains(trimmed, "://") {
		return "", fmt.Errorf("deny_hosts %q: must not include a scheme", raw)
	}
	if strings.Contains(trimmed, "/") {
		return "", fmt.Errorf("deny_hosts %q: must not include a path", raw)
	}
	stars := strings.Count(trimmed, "*")
	if stars > 1 {
		return "", fmt.Errorf(
			"deny_hosts %q: multi-level wildcards are not allowed", raw)
	}
	if stars == 1 && !strings.HasPrefix(trimmed, "*.") {
		return "", fmt.Errorf(
			"deny_hosts %q: only leading `*.<domain>` is supported", raw)
	}
	suffix := strings.TrimPrefix(trimmed, "*.")
	if suffix == "" {
		return "", fmt.Errorf(
			"deny_hosts %q: wildcard `*.` requires a domain suffix", raw)
	}
	// Bracketed IPv6 (`[::1]`) rides through; bare `host:port` does not.
	if strings.Contains(suffix, ":") && !strings.HasPrefix(suffix, "[") {
		return "", fmt.Errorf(
			"deny_hosts %q: must not include a port", raw)
	}
	return trimmed, nil
}

// Active returns the named profile or ErrUnknownProfile.
func (ps *Profiles) Active(name string) (*Profile, error) {
	if ps == nil {
		return nil, ErrUnknownProfile
	}
	if name == "" {
		return nil, ErrUnknownProfile
	}
	p, ok := ps.All[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q (loaded: %v)", ErrUnknownProfile, name, ps.NamesSorted())
	}
	return p, nil
}

// NamesSorted returns the loaded profile names in lexical order.
func (ps *Profiles) NamesSorted() []string {
	if ps == nil {
		return nil
	}
	out := make([]string, 0, len(ps.All))
	for name := range ps.All {
		out = append(out, name)
	}
	// Insertion sort — tiny n + avoids pulling sort into this file's
	// imports.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// DefaultProfilesPath returns ~/.gbounce/profiles.yaml or honors
// GBOUNCE_PROFILES_PATH if set.
func DefaultProfilesPath() (string, error) {
	if override := os.Getenv("GBOUNCE_PROFILES_PATH"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("gbounce: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".gbounce", "profiles.yaml"), nil
}
